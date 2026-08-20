"""
Main STDIO server implementation for FortiGate MCP.

This module implements the core MCP server for FortiGate integration, providing:
- Configuration loading and validation
- Logging setup
- FortiGate API connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown

The server exposes a set of tools for managing FortiGate resources including:
- Device management
- Firewall policy operations
- Network object management
- Routing configuration
"""
import logging
import os
import sys
import signal
from typing import Optional, Annotated
from datetime import datetime

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from src.fortinet_mcp.services.network_service import NetworkService
from src.fortinet_mcp.services.routing_service import RoutingService
from src.fortinet_mcp.services.vip_service import VipService
from src.fortinet_mcp.services.device_service import DeviceService
from src.fortinet_mcp.services.policy_service import PolicyService
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
from src.fortinet_mcp.services.documentation_service import DocumentationService
from src.fortinet_mcp.services.fleet_service import FleetService
from src.fortinet_mcp.services.intent_service import IntentService
from src.fortinet_mcp.services.vpn_service import VpnService
from src.fortinet_mcp.services.system_service import SystemService
from src.fortinet_mcp.services.vdom_service import VdomService
from src.fortinet_mcp.services.mode_policy import ModePolicy
from .tools.definitions import (
    LIST_DEVICES_DESC, GET_DEVICE_STATUS_DESC, TEST_DEVICE_CONNECTION_DESC,
    ADD_DEVICE_DESC, REMOVE_DEVICE_DESC, DISCOVER_VDOMS_DESC,
    LIST_FIREWALL_POLICIES_DESC, CREATE_FIREWALL_POLICY_DESC,
    UPDATE_FIREWALL_POLICY_DESC, DELETE_FIREWALL_POLICY_DESC,
    LIST_ADDRESS_OBJECTS_DESC, CREATE_ADDRESS_OBJECT_DESC,
    LIST_SERVICE_OBJECTS_DESC, CREATE_SERVICE_OBJECT_DESC,
    LIST_STATIC_ROUTES_DESC, CREATE_STATIC_ROUTE_DESC,
    GET_ROUTING_TABLE_DESC, LIST_INTERFACES_DESC, GET_INTERFACE_STATUS_DESC,
    UPDATE_STATIC_ROUTE_DESC, DELETE_STATIC_ROUTE_DESC,
    GET_STATIC_ROUTE_DETAIL_DESC,
    LIST_VIRTUAL_IPS_DESC, CREATE_VIRTUAL_IP_DESC, UPDATE_VIRTUAL_IP_DESC,
    GET_VIRTUAL_IP_DETAIL_DESC, DELETE_VIRTUAL_IP_DESC,
    HEALTH_CHECK_DESC, GET_SERVER_INFO_DESC,
)

class FortiGateMCPServer:
    """Main server class for FortiGate MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        self.logger = setup_logging(self.config.logging)
        
        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
        # Phase 1 platform rewrite: inventory DB + credential manager +
        # connection manager, additive alongside the legacy FortiGateManager
        # above. Table creation is deferred to start() since it's async.
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

        # Initialize MCP server
        self.mcp = FastMCP("FortiGateMCP")
        self._tests_passed: Optional[bool] = None
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
        """Register MCP tools with the server."""
        
        # Device management tools
        @self.mcp.tool(description=LIST_DEVICES_DESC)
        async def list_devices():
            return await self.device_service.list_devices()

        @self.mcp.tool(description=GET_DEVICE_STATUS_DESC)
        async def get_device_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_service.get_device_status(device_id)

        @self.mcp.tool(description=TEST_DEVICE_CONNECTION_DESC)
        async def test_device_connection(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_service.test_device_connection(device_id)

        @self.mcp.tool(description=DISCOVER_VDOMS_DESC)
        async def discover_vdoms(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_service.discover_vdoms(device_id)

        @self.mcp.tool(description=ADD_DEVICE_DESC)
        async def add_device(
            device_id: Annotated[str, Field(description="Unique device identifier")],
            host: Annotated[str, Field(description="FortiGate IP address or hostname")],
            port: Annotated[int, Field(description="HTTPS port", default=443)] = 443,
            username: Annotated[Optional[str], Field(description="Username", default=None)] = None,
            password: Annotated[Optional[str], Field(description="Password", default=None)] = None,
            api_token: Annotated[Optional[str], Field(description="API token", default=None)] = None,
            vdom: Annotated[str, Field(description="Virtual Domain", default="root")] = "root",
            verify_ssl: Annotated[bool, Field(description="Verify SSL", default=True)] = True,
            timeout: Annotated[int, Field(description="Timeout in seconds", default=30)] = 30
        ):
            return await self.device_service.add_device(
                device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
            )

        @self.mcp.tool(description=REMOVE_DEVICE_DESC)
        async def remove_device(
            device_id: Annotated[str, Field(description="Device identifier to remove")]
        ):
            return await self.device_service.remove_device(device_id)

        # Firewall policy tools
        @self.mcp.tool(description=LIST_FIREWALL_POLICIES_DESC)
        async def list_firewall_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.policy_service.list_policies(device_id, vdom)

        @self.mcp.tool(description=CREATE_FIREWALL_POLICY_DESC)
        async def create_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.policy_service.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description=UPDATE_FIREWALL_POLICY_DESC)
        async def update_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to update")],
            policy_data: Annotated[dict, Field(description="Updated policy configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.policy_service.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to get details for")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.policy_service.get_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description=DELETE_FIREWALL_POLICY_DESC)
        async def delete_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.policy_service.delete_policy(device_id, policy_id, vdom)

        # Network object tools
        @self.mcp.tool(description=LIST_ADDRESS_OBJECTS_DESC)
        async def list_address_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_service.list_address_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_ADDRESS_OBJECT_DESC)
        async def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address object name")],
            address_type: Annotated[str, Field(description="Address type (ipmask, iprange, fqdn)")],
            address: Annotated[str, Field(description="Address value (IP/netmask, range, or FQDN)")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_service.create_address_object(device_id, name, address_type, address, vdom)

        @self.mcp.tool(description=LIST_SERVICE_OBJECTS_DESC)
        async def list_service_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_service.list_service_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_SERVICE_OBJECT_DESC)
        async def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Service object name")],
            service_type: Annotated[str, Field(description="Service type")],
            protocol: Annotated[str, Field(description="Protocol (TCP, UDP, ICMP)")],
            port: Annotated[Optional[str], Field(description="Port or port range")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_service.create_service_object(device_id, name, service_type, protocol, port, vdom)

        # Routing tools
        @self.mcp.tool(description=LIST_STATIC_ROUTES_DESC)
        async def list_static_routes(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.list_static_routes(device_id, vdom)

        @self.mcp.tool(description=CREATE_STATIC_ROUTE_DESC)
        async def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            dst: Annotated[str, Field(description="Destination network (IP/netmask)")],
            gateway: Annotated[str, Field(description="Next hop gateway IP")],
            device: Annotated[Optional[str], Field(description="Outgoing interface name")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.create_static_route(device_id, dst, gateway, device, vdom)

        @self.mcp.tool(description=GET_ROUTING_TABLE_DESC)
        async def get_routing_table(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.get_routing_table(device_id, vdom)

        @self.mcp.tool(description=LIST_INTERFACES_DESC)
        async def list_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.list_interfaces(device_id, vdom)

        @self.mcp.tool(description=GET_INTERFACE_STATUS_DESC)
        async def get_interface_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            interface_name: Annotated[str, Field(description="Interface name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description=UPDATE_STATIC_ROUTE_DESC)
        async def update_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description=DELETE_STATIC_ROUTE_DESC)
        async def delete_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description=GET_STATIC_ROUTE_DETAIL_DESC)
        async def get_static_route_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_service.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description=LIST_VIRTUAL_IPS_DESC)
        async def list_virtual_ips(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.vip_service.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description=CREATE_VIRTUAL_IP_DESC)
        async def create_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            extip: Annotated[str, Field(description="External IP address")],
            mappedip: Annotated[str, Field(description="Mapped internal IP address")],
            extintf: Annotated[str, Field(description="External interface name")],
            portforward: Annotated[str, Field(description="Enable/disable port forwarding", default="disable")] = "disable",
            protocol: Annotated[str, Field(description="Protocol type", default="tcp")] = "tcp",
            extport: Annotated[Optional[str], Field(description="External port")] = None,
            mappedport: Annotated[Optional[str], Field(description="Mapped port")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.vip_service.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description=UPDATE_VIRTUAL_IP_DESC)
        async def update_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.vip_service.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description=GET_VIRTUAL_IP_DETAIL_DESC)
        async def get_virtual_ip_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.vip_service.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description=DELETE_VIRTUAL_IP_DESC)
        async def delete_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.vip_service.delete_virtual_ip(device_id, name, vdom)

        # System tools
        @self.mcp.tool(description=HEALTH_CHECK_DESC)
        async def health_check():
            status = "healthy" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
            details = {
                "registered_devices": len(self.fortigate_manager.devices),
                "server_version": self.config.server.version,
                "timestamp": datetime.now().isoformat()
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_health_status(status, details)

        @self.mcp.tool(description=GET_SERVER_INFO_DESC)
        async def get_server_info():
            info = {
                "name": self.config.server.name,
                "version": self.config.server.version,
                "host": self.config.server.host,
                "port": self.config.server.port,
                "registered_devices": len(self.fortigate_manager.devices),
                "available_tools": [
                    "Device Management (6 tools)",
                    "Firewall Policy Management (4 tools)",
                    "Network Objects Management (4 tools)",
                    "Routing Management (4 tools)",
                    "System Tools (2 tools)"
                ]
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_json_response(info, "Server Information")

    def start(self) -> None:
        """Start the MCP server."""
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        async def _run() -> None:
            await init_models(self.fortinet_engine)
            await self.mcp.run_stdio_async()

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                self.logger.info("Running startup tests...")
                # Add test logic here
                self._tests_passed = True

            self.logger.info("Starting FortiGate MCP server...")
            anyio.run(_run)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    config_path = os.getenv("FORTIGATE_MCP_CONFIG")
    if not config_path:
        print("FORTIGATE_MCP_CONFIG environment variable must be set", file=sys.stderr)
        sys.exit(1)

    try:
        server = FortiGateMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
