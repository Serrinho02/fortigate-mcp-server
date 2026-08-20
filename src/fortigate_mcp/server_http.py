"""
HTTP-based MCP server implementation for FortiGate MCP.

This module provides an HTTP transport layer for the MCP server,
supporting HTTP transport for web-based integrations and external access.
"""

import json
import os
import sys
import signal
from typing import Optional
from datetime import datetime

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from src.fortinet_mcp.services.network_service import NetworkService
from src.fortinet_mcp.services.routing_service import RoutingService
from src.fortinet_mcp.services.vip_service import VipService
from src.fortinet_mcp.adapters.registry import AdapterRegistry
from src.fortinet_mcp.adapters.fortios.factory import register_fortios_adapter
from src.fortinet_mcp.infra.connection_manager import ConnectionManager
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from src.fortinet_mcp.infra.db import create_engine as create_fortinet_engine
from src.fortinet_mcp.infra.db import create_session_factory, init_models
from src.fortinet_mcp.mcp.tools.analysis_tools import register_analysis_tools
from src.fortinet_mcp.mcp.tools.change_tools import register_change_tools
from src.fortinet_mcp.services.analysis_service import AnalysisService
from src.fortinet_mcp.mcp.tools.connection_tools import register_connection_tools
from src.fortinet_mcp.mcp.tools.doc_tools import register_doc_tools
from src.fortinet_mcp.mcp.tools.fleet_tools import register_fleet_tools
from src.fortinet_mcp.mcp.tools.intent_tools import register_intent_tools
from src.fortinet_mcp.mcp.tools.vpn_tools import register_vpn_tools
from src.fortinet_mcp.mcp.tools.system_tools import register_system_tools
from src.fortinet_mcp.mcp.tools.vdom_tools import register_vdom_tools
from src.fortinet_mcp.mcp.tools.routing_tools import register_routing_tools
from src.fortinet_mcp.mcp.tools.inventory_tools import register_inventory_tools
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.device_service import DeviceService
from src.fortinet_mcp.services.documentation_service import DocumentationService
from src.fortinet_mcp.services.fleet_service import FleetService
from src.fortinet_mcp.services.intent_service import IntentService
from src.fortinet_mcp.services.vpn_service import VpnService
from src.fortinet_mcp.services.system_service import SystemService
from src.fortinet_mcp.services.vdom_service import VdomService
from src.fortinet_mcp.services.mode_policy import ModePolicy
from src.fortinet_mcp.services.policy_service import PolicyService

class FortiGateMCPHTTPServer:
    """
    HTTP-based MCP server for FortiGate management.
    
    This server supports:
    - HTTP transport for web integration
    - CORS for browser access
    - Authentication (optional)
    - Rate limiting
    """
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8814,
                 path: str = "/fortigate-mcp"):
        """
        Initialize the HTTP MCP server.
        
        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        if not FASTMCP_AVAILABLE:
            raise RuntimeError("FastMCP is not available. Please install fastmcp package.")
            
        # Load and validate configuration
        self.config = load_config(config_path)
        
        # Setup logging
        self.logger = setup_logging(self.config.logging)
        
        self.host = host
        self.port = port
        self.path = path
        
        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
        # Phase 1 platform rewrite: inventory DB + credential manager +
        # connection manager, additive alongside the legacy FortiGateManager
        # above. Table creation happens once in run(), before the HTTP
        # transport's own event loop starts.
        self.fortinet_engine = create_fortinet_engine()
        self.fortinet_session_factory = create_session_factory(self.fortinet_engine)
        self.credential_manager = CredentialManager()
        self.adapter_registry = AdapterRegistry()
        register_fortios_adapter(self.adapter_registry)
        self.connection_manager = ConnectionManager(
            self.fortinet_session_factory, self.credential_manager, self.adapter_registry
        )

        # Phase 3: READ_ONLY/SAFE/FULL enforcement + the preview/apply/rollback
        # change engine. Every mutating service below routes through this.
        self.mode_policy = ModePolicy.from_env()
        self.change_service = ChangeService(
            self.fortigate_manager,
            self.fortinet_session_factory,
            self.mode_policy,
            connection_manager=self.connection_manager,
        )

        # Initialize tools
        # NOTE: device domain migrated to services.device_service.DeviceService (Phase 2)
        self.device_service = DeviceService(self.fortigate_manager, connection_manager=self.connection_manager)
        # NOTE: firewall policy domain migrated to services.policy_service.PolicyService (Phase 2);
        # create/update/delete now go through ChangeService (Phase 3)
        self.policy_service = PolicyService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )
        # NOTE: network object domain migrated to services.network_service.NetworkService (Phase 2/3)
        self.network_service = NetworkService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )
        # NOTE: routing domain migrated to services.routing_service.RoutingService (Phase 2/3)
        self.routing_service = RoutingService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )
        # NOTE: virtual IP domain migrated to services.vip_service.VipService (Phase 2/3)
        self.vip_service = VipService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )
        # NOTE: Phase 4 -- read-only analysis engine, no change_service needed
        self.analysis_service = AnalysisService(self.fortigate_manager, connection_manager=self.connection_manager)
        # NOTE: Phase 5 -- read-only documentation/diagram generation, no change_service needed
        self.documentation_service = DocumentationService(
            self.fortigate_manager, connection_manager=self.connection_manager
        )
        # NOTE: Phase 6 -- fleet operations resolve devices via ConnectionManager/
        # the inventory DB, not the legacy FortiGateManager (see fleet_service.py)
        self.fleet_service = FleetService(self.connection_manager, self.mode_policy)
        # NOTE: Phase 7 -- composes policy_service, so intent.create_policy still
        # routes through the change engine
        self.intent_service = IntentService(
            self.fortigate_manager, self.policy_service, connection_manager=self.connection_manager
        )
        # NOTE: IPsec VPN CRUD routes through the change engine like PolicyService
        self.vpn_service = VpnService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )
        # NOTE: system.* domain (DNS/NTP/syslog/SNMP/global/admin/HA) -- new
        # "day-0 configuration" effort, same change-engine gating as everything above
        self.system_service = SystemService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )
        # NOTE: VDOM lifecycle + inter-VDOM links (Phase B of the same effort)
        self.vdom_service = VdomService(
            self.fortigate_manager, self.change_service, connection_manager=self.connection_manager
        )

        # Initialize FastMCP
        self.mcp = FastMCP("FortiGateMCP-HTTP")

        # Setup tools
        self._setup_tools()
        register_inventory_tools(
            self.mcp, self.fortinet_session_factory, self.credential_manager
        )
        register_connection_tools(self.mcp, self.connection_manager)
        register_change_tools(self.mcp, self.change_service)
        register_analysis_tools(self.mcp, self.analysis_service)
        register_doc_tools(self.mcp, self.documentation_service)
        register_fleet_tools(self.mcp, self.fleet_service)
        register_intent_tools(self.mcp, self.intent_service)
        register_vpn_tools(self.mcp, self.vpn_service)
        register_system_tools(self.mcp, self.system_service)
        register_vdom_tools(self.mcp, self.vdom_service)
        register_routing_tools(self.mcp, self.routing_service)

    def _setup_tools(self) -> None:
        """Register MCP tools with appropriate descriptions."""
        
        # Device tools
        @self.mcp.tool(description="List all registered FortiGate devices")
        async def list_devices():
            return await self.device_service.list_devices()

        @self.mcp.tool(description="Get device system status")
        async def get_device_status(device_id: str):
            return await self.device_service.get_device_status(device_id)

        @self.mcp.tool(description="Test device connection")
        async def test_device_connection(device_id: str):
            return await self.device_service.test_device_connection(device_id)

        @self.mcp.tool(description="Discover device VDOMs")
        async def discover_vdoms(device_id: str):
            return await self.device_service.discover_vdoms(device_id)

        @self.mcp.tool(description="Add a new FortiGate device")
        async def add_device(device_id: str, host: str, port: int = 443,
                      username: Optional[str] = None, password: Optional[str] = None,
                      api_token: Optional[str] = None, vdom: str = "root",
                      verify_ssl: bool = True, timeout: int = 30):
            return await self.device_service.add_device(device_id, host, port, username, password,
                                              api_token, vdom, verify_ssl, timeout)

        @self.mcp.tool(description="Remove a FortiGate device")
        async def remove_device(device_id: str):
            return await self.device_service.remove_device(device_id)

        # Firewall tools
        @self.mcp.tool(description="List firewall policies")
        async def list_firewall_policies(device_id: str, vdom: Optional[str] = None):
            return await self.policy_service.list_policies(device_id, vdom)

        @self.mcp.tool(description="Create firewall policy")
        async def create_firewall_policy(device_id: str, policy_data: dict, vdom: Optional[str] = None):
            return await self.policy_service.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="Update firewall policy")
        async def update_firewall_policy(device_id: str, policy_id: str, policy_data: dict, vdom: Optional[str] = None):
            return await self.policy_service.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(device_id: str, policy_id: str, vdom: Optional[str] = None):
            return await self.policy_service.get_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="Delete firewall policy")
        async def delete_firewall_policy(device_id: str, policy_id: str, vdom: Optional[str] = None):
            return await self.policy_service.delete_policy(device_id, policy_id, vdom)

        # Network tools
        @self.mcp.tool(description="List address objects")
        async def list_address_objects(device_id: str, vdom: Optional[str] = None):
            return await self.network_service.list_address_objects(device_id, vdom)

        @self.mcp.tool(description="Create address object")
        async def create_address_object(device_id: str, name: str, address_type: str, address: str, vdom: Optional[str] = None):
            return await self.network_service.create_address_object(device_id, name, address_type, address, vdom)

        @self.mcp.tool(description="List service objects")
        async def list_service_objects(device_id: str, vdom: Optional[str] = None):
            return await self.network_service.list_service_objects(device_id, vdom)

        @self.mcp.tool(description="Create service object")
        async def create_service_object(device_id: str, name: str, service_type: str, protocol: str,
                                port: Optional[str] = None, vdom: Optional[str] = None):
            return await self.network_service.create_service_object(device_id, name, service_type, protocol, port, vdom)

        # Routing tools
        @self.mcp.tool(description="List static routes")
        async def list_static_routes(device_id: str, vdom: Optional[str] = None):
            return await self.routing_service.list_static_routes(device_id, vdom)

        @self.mcp.tool(description="Create static route")
        async def create_static_route(device_id: str, dst: str, gateway: str, device: Optional[str] = None, vdom: Optional[str] = None):
            return await self.routing_service.create_static_route(device_id, dst, gateway, device, vdom)

        @self.mcp.tool(description="Get routing table")
        async def get_routing_table(device_id: str, vdom: Optional[str] = None):
            return await self.routing_service.get_routing_table(device_id, vdom)

        @self.mcp.tool(description="List network interfaces")
        async def list_interfaces(device_id: str, vdom: Optional[str] = None):
            return await self.routing_service.list_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get interface status")
        async def get_interface_status(device_id: str, interface_name: str, vdom: Optional[str] = None):
            return await self.routing_service.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description="Update static route")
        async def update_static_route(device_id: str, route_id: str, route_data: dict, vdom: Optional[str] = None):
            return await self.routing_service.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description="Delete static route")
        async def delete_static_route(device_id: str, route_id: str, vdom: Optional[str] = None):
            return await self.routing_service.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description="Get static route detail")
        async def get_static_route_detail(device_id: str, route_id: str, vdom: Optional[str] = None):
            return await self.routing_service.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description="List virtual IPs")
        async def list_virtual_ips(device_id: str, vdom: Optional[str] = None):
            return await self.vip_service.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description="Create virtual IP")
        async def create_virtual_ip(device_id: str, name: str, extip: str, mappedip: str,
                             extintf: str, portforward: str = "disable",
                             protocol: str = "tcp", extport: Optional[str] = None,
                             mappedport: Optional[str] = None, vdom: Optional[str] = None):
            return await self.vip_service.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description="Update virtual IP")
        async def update_virtual_ip(device_id: str, name: str, vip_data: dict, vdom: Optional[str] = None):
            return await self.vip_service.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description="Get virtual IP detail")
        async def get_virtual_ip_detail(device_id: str, name: str, vdom: Optional[str] = None):
            return await self.vip_service.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description="Delete virtual IP")
        async def delete_virtual_ip(device_id: str, name: str, vdom: Optional[str] = None):
            return await self.vip_service.delete_virtual_ip(device_id, name, vdom)

        # System tools
        @self.mcp.tool(description="Test FortiGate connection")
        async def test_connection():
            try:
                devices = self.fortigate_manager.list_devices()
                connection_results = {}

                for device_id in devices:
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = await api_client.test_connection()
                        connection_results[device_id] = {
                            "connected": success,
                            "status": "connected" if success else "failed"
                        }
                    except Exception as e:
                        connection_results[device_id] = {
                            "connected": False,
                            "status": "error",
                            "error": str(e)
                        }

                return self._format_response({
                    "devices": connection_results,
                    "total_devices": len(devices)
                }, "test_connection")
            except Exception as e:
                return self._format_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection")

        @self.mcp.tool(description="Health check for FortiGate MCP server")
        async def health():
            health_info = {
                "status": "ok",
                "server": "FortiGateMCP-HTTP",
                "timestamp": datetime.now().isoformat(),
                "registered_devices": len(self.fortigate_manager.devices),
                "device_connections": {}
            }

            # Test device connections
            try:
                devices = self.fortigate_manager.list_devices()
                for device_id in devices:
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = await api_client.test_connection()
                        health_info["device_connections"][device_id] = "connected" if success else "disconnected"
                    except Exception as e:
                        health_info["device_connections"][device_id] = "error"
                        health_info["status"] = "degraded"
            except Exception as e:
                health_info["status"] = "error"
                health_info["error"] = str(e)

            return self._format_response(health_info, "health")

    def _format_response(self, data, operation: str = "operation"):
        """Format response data for MCP."""
        from mcp.types import TextContent as Content
        
        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def run(self) -> None:
        """
        Start the HTTP MCP server.
        
        Runs the server with HTTP transport on the configured
        host and port.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting FortiGate MCP HTTP server on {self.host}:{self.port}{self.path}")
            self.logger.info(f"Registered devices: {len(self.fortigate_manager.devices)}")

            # Create the inventory tables once, before the HTTP transport
            # below starts its own event loop.
            import anyio
            anyio.run(init_models, self.fortinet_engine)

            # Run with FastMCP's built-in HTTP transport
            self.mcp.run(
                transport="http",
                host=self.host,
                port=self.port,
                path=self.path
            )
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            sys.exit(1)


class FortiGateMCPCommand:
    """
    Command runner for FortiGate MCP HTTP server.
    
    This class can be used as a standalone command runner.
    """
    
    help = "FortiGate MCP HTTP Server"
    
    def __init__(self):
        self.server = None
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8814,
            help='Server port (default: 8814)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/fortigate-mcp',
            help='HTTP path (default: /fortigate-mcp)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('FORTIGATE_MCP_CONFIG')
        
        self.server = FortiGateMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8814),
            path=options.get('path', '/fortigate-mcp')
        )
        
        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FortiGate MCP HTTP Server')
    command = FortiGateMCPCommand()
    command.add_arguments(parser)
    
    args = parser.parse_args()
    options = vars(args)
    
    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
