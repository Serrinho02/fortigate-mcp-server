"""
FortiGate API management for the MCP server.

This module provides the core FortiGate API integration:
- Device connection management with persistent async HTTP clients
- Authentication handling (API token or basic auth)
- API session management with connection pooling
- Request/response processing
- Error handling and recovery
"""
import logging
import time
from typing import Dict, Any, Optional, Union, List
import httpx
import json
from ..config.models import FortiGateDeviceConfig, AuthConfig
from .logging import get_logger, log_api_call

class FortiGateAPIError(Exception):
    """Custom exception for FortiGate API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None,
                 device_id: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.device_id = device_id

class FortiGateAPI:
    """FortiGate API client for individual device communication.

    Handles all HTTP communication with a single FortiGate device using
    a persistent async HTTP client with connection pooling:
    - Authentication management
    - Request/response processing
    - Error handling and retries
    - Session management
    """

    def __init__(self, device_id: str, config: FortiGateDeviceConfig):
        """Initialize FortiGate API client.

        Args:
            device_id: Unique identifier for this device
            config: Device configuration including connection details
        """
        self.device_id = device_id
        self.config = config
        self.logger = get_logger(f"device.{device_id}")

        # Build base URL
        self.base_url = f"https://{config.host}:{config.port}/api/v2"

        # Setup authentication headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        if config.api_token:
            self.headers["Authorization"] = f"Bearer {config.api_token}"
            self.auth_method = "token"
        elif config.username and config.password:
            self.auth_method = "basic"
            self._basic_auth = (config.username, config.password)
        else:
            raise ValueError(f"Device {device_id}: Either api_token or username/password must be provided")

        if not config.verify_ssl:
            self.logger.warning(f"SSL verification disabled for device {device_id} - NOT recommended for production")

        # Create persistent async HTTP client with connection pooling
        self._client = httpx.AsyncClient(
            verify=config.verify_ssl,
            timeout=config.timeout,
            headers=self.headers,
            auth=(config.username, config.password) if self.auth_method == "basic" else None,
        )

        self.logger.info(f"Initialized FortiGate API client (auth: {self.auth_method})")

    async def close(self):
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to FortiGate API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (without /api/v2 prefix)
            params: Query parameters
            data: Request body data
            vdom: Virtual Domain (uses device default if not specified)

        Returns:
            API response as dictionary

        Raises:
            FortiGateAPIError: If API request fails
        """
        # Build URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        # Setup parameters
        if not params:
            params = {}
        params["vdom"] = vdom or self.config.vdom

        start_time = time.time()

        try:
            response = await self._client.request(
                method=method,
                url=url,
                params=params,
                json=data if data else None
            )

            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, response.status_code, duration_ms)

            # Handle error responses
            if response.status_code >= 400:
                error_msg = f"API request failed: {response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg += f" - {error_data['error']}"
                except Exception:
                    error_msg += f" - {response.text}"

                raise FortiGateAPIError(
                    error_msg,
                    status_code=response.status_code,
                    device_id=self.device_id
                )

            # Parse response
            try:
                return response.json()
            except json.JSONDecodeError:
                # Some endpoints may return empty responses
                return {"status": "success"}

        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, None, duration_ms)
            raise FortiGateAPIError(
                f"Network error: {str(e)}",
                device_id=self.device_id
            )

    async def test_connection(self) -> bool:
        """Test connection to FortiGate device.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            await self.get_system_status()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    # System endpoints
    async def get_system_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system status information."""
        return await self._make_request("GET", "monitor/system/status", vdom=vdom)

    async def get_system_interface(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system interface information."""
        return await self._make_request("GET", "monitor/system/interface", vdom=vdom)

    async def get_vdoms(self) -> Dict[str, Any]:
        """Get list of Virtual Domains."""
        return await self._make_request("GET", "cmdb/system/vdom")

    async def create_vdom(self, vdom_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new VDOM. Requires the device to already be in
        multi-vdom mode (system/global vdom-mode) -- see VdomService."""
        return await self._make_request("POST", "cmdb/system/vdom", data=vdom_data)

    async def delete_vdom(self, name: str) -> Dict[str, Any]:
        """Delete a VDOM by name."""
        return await self._make_request("DELETE", f"cmdb/system/vdom/{name}")

    # Inter-VDOM links (a pair of virtual interfaces joining two VDOMs)
    async def get_vdom_links(self) -> Dict[str, Any]:
        """List inter-VDOM links."""
        return await self._make_request("GET", "cmdb/system/vdom-link")

    async def get_vdom_link_detail(self, name: str) -> Dict[str, Any]:
        """Get a single inter-VDOM link by name."""
        return await self._make_request("GET", f"cmdb/system/vdom-link/{name}")

    async def create_vdom_link(self, link_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an inter-VDOM link. FortiOS creates a pair of virtual
        interfaces (`<name>0`/`<name>1`) that must then each be assigned to
        one of the two VDOMs being joined via update_interface (see
        RoutingService, Phase C of this effort)."""
        return await self._make_request("POST", "cmdb/system/vdom-link", data=link_data)

    async def delete_vdom_link(self, name: str) -> Dict[str, Any]:
        """Delete an inter-VDOM link by name."""
        return await self._make_request("DELETE", f"cmdb/system/vdom-link/{name}")

    # Interface endpoints
    async def get_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get interface configuration."""
        return await self._make_request("GET", "cmdb/system/interface", vdom=vdom)

    async def get_interface_status(self, interface_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get specific interface status."""
        return await self._make_request("GET", f"monitor/system/interface?interface={interface_name}", vdom=vdom)

    async def get_interface_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a single interface's cmdb configuration (IP, role, VDOM
        assignment, VLAN id, ...) -- distinct from get_interface_status,
        which is live monitor data."""
        return await self._make_request("GET", f"cmdb/system/interface/{name}", vdom=vdom)

    async def create_interface(self, interface_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create an interface (VLAN sub-interface, loopback, or a
        vdom-link member interface -- not a new physical port, FortiOS
        doesn't allow that)."""
        return await self._make_request("POST", "cmdb/system/interface", data=interface_data, vdom=vdom)

    async def update_interface(
        self, name: str, interface_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update an interface's configuration (IP/netmask, role, VDOM
        assignment, allowed access, ...)."""
        return await self._make_request("PUT", f"cmdb/system/interface/{name}", data=interface_data, vdom=vdom)

    async def delete_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete an interface. FortiOS rejects this for physical ports;
        only VLAN/loopback/vdom-link member interfaces can actually be
        deleted -- the rejection surfaces as a normal API error."""
        return await self._make_request("DELETE", f"cmdb/system/interface/{name}", vdom=vdom)

    # Zones (interface groupings used by policies)
    async def get_zones(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """List zones."""
        return await self._make_request("GET", "cmdb/system/zone", vdom=vdom)

    async def get_zone_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a single zone by name."""
        return await self._make_request("GET", f"cmdb/system/zone/{name}", vdom=vdom)

    async def create_zone(self, zone_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a zone (name + member interfaces)."""
        return await self._make_request("POST", "cmdb/system/zone", data=zone_data, vdom=vdom)

    async def update_zone(self, name: str, zone_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update a zone's member interfaces."""
        return await self._make_request("PUT", f"cmdb/system/zone/{name}", data=zone_data, vdom=vdom)

    async def delete_zone(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a zone."""
        return await self._make_request("DELETE", f"cmdb/system/zone/{name}", vdom=vdom)

    # DHCP server (keyed by FortiOS's numeric id, e.g. "1")
    async def get_dhcp_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """List DHCP servers."""
        return await self._make_request("GET", "cmdb/system.dhcp/server", vdom=vdom)

    async def get_dhcp_server_detail(self, server_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a single DHCP server by id."""
        return await self._make_request("GET", f"cmdb/system.dhcp/server/{server_id}", vdom=vdom)

    async def create_dhcp_server(self, server_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a DHCP server (interface, ip-range, netmask, default-gateway, dns-server1, ...)."""
        return await self._make_request("POST", "cmdb/system.dhcp/server", data=server_data, vdom=vdom)

    async def update_dhcp_server(
        self, server_id: str, server_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a DHCP server."""
        return await self._make_request("PUT", f"cmdb/system.dhcp/server/{server_id}", data=server_data, vdom=vdom)

    async def delete_dhcp_server(self, server_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a DHCP server."""
        return await self._make_request("DELETE", f"cmdb/system.dhcp/server/{server_id}", vdom=vdom)

    # Firewall policy endpoints
    async def get_firewall_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policies."""
        return await self._make_request("GET", "cmdb/firewall/policy", vdom=vdom)

    async def create_firewall_policy(self, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new firewall policy."""
        return await self._make_request("POST", "cmdb/firewall/policy", data=policy_data, vdom=vdom)

    async def update_firewall_policy(self, policy_id: str, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing firewall policy."""
        return await self._make_request("PUT", f"cmdb/firewall/policy/{policy_id}", data=policy_data, vdom=vdom)

    async def get_firewall_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific firewall policy."""
        return await self._make_request("GET", f"cmdb/firewall/policy/{policy_id}", vdom=vdom)

    async def delete_firewall_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete firewall policy."""
        return await self._make_request("DELETE", f"cmdb/firewall/policy/{policy_id}", vdom=vdom)

    # Address object endpoints
    async def get_address_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address objects."""
        return await self._make_request("GET", "cmdb/firewall/address", vdom=vdom)

    async def create_address_object(self, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new address object."""
        return await self._make_request("POST", "cmdb/firewall/address", data=address_data, vdom=vdom)

    async def update_address_object(self, address_name: str, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing address object."""
        return await self._make_request("PUT", f"cmdb/firewall/address/{address_name}", data=address_data, vdom=vdom)

    async def delete_address_object(self, address_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete address object."""
        return await self._make_request("DELETE", f"cmdb/firewall/address/{address_name}", vdom=vdom)

    # Service object endpoints
    async def get_service_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get service objects."""
        return await self._make_request("GET", "cmdb/firewall.service/custom", vdom=vdom)

    async def create_service_object(self, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new service object."""
        return await self._make_request("POST", "cmdb/firewall.service/custom", data=service_data, vdom=vdom)

    async def update_service_object(self, service_name: str, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing service object."""
        return await self._make_request("PUT", f"cmdb/firewall.service/custom/{service_name}", data=service_data, vdom=vdom)

    async def delete_service_object(self, service_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete service object."""
        return await self._make_request("DELETE", f"cmdb/firewall.service/custom/{service_name}", vdom=vdom)

    # Routing endpoints
    async def get_static_routes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get static routes."""
        return await self._make_request("GET", "cmdb/router/static", vdom=vdom)

    async def create_static_route(self, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new static route."""
        return await self._make_request("POST", "cmdb/router/static", data=route_data, vdom=vdom)

    async def update_static_route(self, route_id: str, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing static route."""
        return await self._make_request("PUT", f"cmdb/router/static/{route_id}", data=route_data, vdom=vdom)

    async def delete_static_route(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete static route."""
        return await self._make_request("DELETE", f"cmdb/router/static/{route_id}", vdom=vdom)

    async def get_static_route_detail(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific static route."""
        return await self._make_request("GET", f"cmdb/router/static/{route_id}", vdom=vdom)

    async def get_routing_table(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get routing table."""
        return await self._make_request("GET", "monitor/router/ipv4", vdom=vdom)

    # Virtual IP endpoints
    async def get_virtual_ips(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get virtual IPs."""
        return await self._make_request("GET", "cmdb/firewall/vip", vdom=vdom)

    async def create_virtual_ip(self, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new virtual IP."""
        return await self._make_request("POST", "cmdb/firewall/vip", data=vip_data, vdom=vdom)

    async def update_virtual_ip(self, vip_name: str, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing virtual IP."""
        return await self._make_request("PUT", f"cmdb/firewall/vip/{vip_name}", data=vip_data, vdom=vdom)

    async def delete_virtual_ip(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete virtual IP."""
        return await self._make_request("DELETE", f"cmdb/firewall/vip/{vip_name}", vdom=vdom)

    async def get_virtual_ip_detail(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific virtual IP."""
        return await self._make_request("GET", f"cmdb/firewall/vip/{vip_name}", vdom=vdom)

    # IPsec VPN phase1 (tunnel/gateway) endpoints
    async def get_ipsec_phase1_list(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPsec phase1-interface (tunnel/gateway) definitions."""
        return await self._make_request("GET", "cmdb/vpn.ipsec/phase1-interface", vdom=vdom)

    async def get_ipsec_phase1_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific IPsec phase1-interface definition."""
        return await self._make_request("GET", f"cmdb/vpn.ipsec/phase1-interface/{name}", vdom=vdom)

    async def create_ipsec_phase1(self, phase1_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a new IPsec phase1-interface (tunnel/gateway)."""
        return await self._make_request("POST", "cmdb/vpn.ipsec/phase1-interface", data=phase1_data, vdom=vdom)

    async def update_ipsec_phase1(self, name: str, phase1_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing IPsec phase1-interface."""
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/phase1-interface/{name}", data=phase1_data, vdom=vdom)

    async def delete_ipsec_phase1(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete an IPsec phase1-interface."""
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/phase1-interface/{name}", vdom=vdom)

    # IPsec VPN phase2 (traffic selector) endpoints
    async def get_ipsec_phase2_list(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPsec phase2-interface (traffic selector) definitions."""
        return await self._make_request("GET", "cmdb/vpn.ipsec/phase2-interface", vdom=vdom)

    async def get_ipsec_phase2_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific IPsec phase2-interface definition."""
        return await self._make_request("GET", f"cmdb/vpn.ipsec/phase2-interface/{name}", vdom=vdom)

    async def create_ipsec_phase2(self, phase2_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a new IPsec phase2-interface (traffic selector), linked to a phase1 by name."""
        return await self._make_request("POST", "cmdb/vpn.ipsec/phase2-interface", data=phase2_data, vdom=vdom)

    async def update_ipsec_phase2(self, name: str, phase2_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing IPsec phase2-interface."""
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/phase2-interface/{name}", data=phase2_data, vdom=vdom)

    async def delete_ipsec_phase2(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete an IPsec phase2-interface."""
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/phase2-interface/{name}", vdom=vdom)

    # IPsec live tunnel status (read-only monitor endpoint)
    async def get_ipsec_tunnel_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get live IPsec tunnel status (up/down, traffic counters)."""
        return await self._make_request("GET", "monitor/vpn/ipsec", vdom=vdom)

    # SSL VPN endpoints
    async def get_ssl_vpn_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get SSL VPN settings (a single object per VDOM, not a list)."""
        return await self._make_request("GET", "cmdb/vpn.ssl/settings", vdom=vdom)

    async def update_ssl_vpn_settings(self, settings_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update SSL VPN settings."""
        return await self._make_request("PUT", "cmdb/vpn.ssl/settings", data=settings_data, vdom=vdom)

    async def get_ssl_vpn_sessions(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get active SSL VPN sessions (read-only monitor endpoint)."""
        return await self._make_request("GET", "monitor/vpn/ssl", vdom=vdom)

    # DNS settings (singleton per VDOM)
    async def get_dns_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS server settings."""
        return await self._make_request("GET", "cmdb/system/dns", vdom=vdom)

    async def update_dns_settings(self, dns_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DNS server settings."""
        return await self._make_request("PUT", "cmdb/system/dns", data=dns_data, vdom=vdom)

    # NTP settings (singleton, global)
    async def get_ntp_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get NTP settings."""
        return await self._make_request("GET", "cmdb/system/ntp", vdom=vdom)

    async def update_ntp_settings(self, ntp_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update NTP settings."""
        return await self._make_request("PUT", "cmdb/system/ntp", data=ntp_data, vdom=vdom)

    # Syslog settings (singleton)
    async def get_syslog_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get syslogd (remote logging) settings."""
        return await self._make_request("GET", "cmdb/log.syslogd/setting", vdom=vdom)

    async def update_syslog_settings(self, syslog_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update syslogd (remote logging) settings."""
        return await self._make_request("PUT", "cmdb/log.syslogd/setting", data=syslog_data, vdom=vdom)

    # SNMP sysinfo (singleton, global) + communities (keyed, global)
    async def get_snmp_sysinfo(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get global SNMP agent settings (enable/description/contact/location)."""
        return await self._make_request("GET", "cmdb/system.snmp/sysinfo", vdom=vdom)

    async def update_snmp_sysinfo(self, sysinfo_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update global SNMP agent settings."""
        return await self._make_request("PUT", "cmdb/system.snmp/sysinfo", data=sysinfo_data, vdom=vdom)

    async def get_snmp_communities(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """List SNMP v1/v2c communities."""
        return await self._make_request("GET", "cmdb/system.snmp/community", vdom=vdom)

    async def get_snmp_community_detail(self, community_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a single SNMP v1/v2c community by id."""
        return await self._make_request("GET", f"cmdb/system.snmp/community/{community_id}", vdom=vdom)

    async def create_snmp_community(self, community_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create an SNMP v1/v2c community."""
        return await self._make_request("POST", "cmdb/system.snmp/community", data=community_data, vdom=vdom)

    async def update_snmp_community(self, community_id: str, community_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update an SNMP v1/v2c community."""
        return await self._make_request("PUT", f"cmdb/system.snmp/community/{community_id}", data=community_data, vdom=vdom)

    async def delete_snmp_community(self, community_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete an SNMP v1/v2c community."""
        return await self._make_request("DELETE", f"cmdb/system.snmp/community/{community_id}", vdom=vdom)

    # System global settings (singleton, global -- hostname, timezone, admin ports, ...)
    async def get_system_global(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get global system settings (hostname, timezone, admin/mgmt ports, vdom-mode, ...)."""
        return await self._make_request("GET", "cmdb/system/global", vdom=vdom)

    async def update_system_global(self, global_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update global system settings. Can affect the current management
        session (hostname, admin port changes, vdom-mode) -- see SystemService
        docstring for the operational warning surfaced to callers."""
        return await self._make_request("PUT", "cmdb/system/global", data=global_data, vdom=vdom)

    # Admin users (keyed by username, global)
    async def list_admins(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """List local admin (management user) accounts."""
        return await self._make_request("GET", "cmdb/system/admin", vdom=vdom)

    async def get_admin_detail(self, username: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a single admin account by username."""
        return await self._make_request("GET", f"cmdb/system/admin/{username}", vdom=vdom)

    async def create_admin(self, admin_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a local admin account. `password` is write-only, same
        visibility tradeoff as an IPsec psksecret -- see SystemService."""
        return await self._make_request("POST", "cmdb/system/admin", data=admin_data, vdom=vdom)

    async def update_admin(self, username: str, admin_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update a local admin account."""
        return await self._make_request("PUT", f"cmdb/system/admin/{username}", data=admin_data, vdom=vdom)

    async def delete_admin(self, username: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a local admin account."""
        return await self._make_request("DELETE", f"cmdb/system/admin/{username}", vdom=vdom)

    # HA configuration (singleton, global)
    async def get_ha_config(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get high-availability (HA) cluster configuration."""
        return await self._make_request("GET", "cmdb/system/ha", vdom=vdom)

    async def update_ha_config(self, ha_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update HA cluster configuration. Misconfiguration can affect
        cluster membership/reachability -- see SystemService docstring."""
        return await self._make_request("PUT", "cmdb/system/ha", data=ha_data, vdom=vdom)


class FortiGateManager:
    """Manager for multiple FortiGate devices.

    Handles device registration, connection management, and provides
    unified access to multiple FortiGate devices.
    """

    def __init__(self, devices: Dict[str, FortiGateDeviceConfig], auth_config: AuthConfig):
        """Initialize FortiGate manager.

        Args:
            devices: Dictionary of device configurations
            auth_config: Authentication configuration
        """
        self.devices: Dict[str, FortiGateAPI] = {}
        self.auth_config = auth_config
        self.logger = get_logger("fortigate_manager")

        # Initialize devices
        for device_id, config in devices.items():
            try:
                self.devices[device_id] = FortiGateAPI(device_id, config)
                self.logger.info(f"Initialized device: {device_id}")
            except Exception as e:
                self.logger.error(f"Failed to initialize device {device_id}: {e}")

    def get_device(self, device_id: str) -> FortiGateAPI:
        """Get FortiGate API client for a device.

        Args:
            device_id: Device identifier

        Returns:
            FortiGateAPI client instance

        Raises:
            ValueError: If device not found
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")
        return self.devices[device_id]

    def list_devices(self) -> List[str]:
        """List all registered device IDs.

        Returns:
            List of device identifiers
        """
        return list(self.devices.keys())

    def add_device(self, device_id: str, host: str, port: int = 443,
                   username: Optional[str] = None, password: Optional[str] = None,
                   api_token: Optional[str] = None, vdom: str = "root",
                   verify_ssl: bool = True, timeout: int = 30) -> None:
        """Add a new device to the manager.

        Args:
            device_id: Unique identifier for the device
            host: Device IP address or hostname
            port: HTTPS port
            username: Username for authentication
            password: Password for authentication
            api_token: API token for authentication
            vdom: Virtual Domain name
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if device_id in self.devices:
            raise ValueError(f"Device '{device_id}' already exists")

        # Create device configuration
        device_config = FortiGateDeviceConfig(
            host=host,
            port=port,
            username=username,
            password=password,
            api_token=api_token,
            vdom=vdom,
            verify_ssl=verify_ssl,
            timeout=timeout
        )

        # Create API client
        self.devices[device_id] = FortiGateAPI(device_id, device_config)
        self.logger.info(f"Added device: {device_id}")

    async def remove_device(self, device_id: str) -> None:
        """Remove a device from the manager and close its connection.

        Args:
            device_id: Device identifier to remove
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")

        await self.devices[device_id].close()
        del self.devices[device_id]
        self.logger.info(f"Removed device: {device_id}")

    async def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all devices.

        Returns:
            Dictionary mapping device IDs to connection status
        """
        results = {}
        for device_id, api_client in self.devices.items():
            try:
                results[device_id] = await api_client.test_connection()
            except Exception as e:
                self.logger.error(f"Connection test failed for {device_id}: {e}")
                results[device_id] = False
        return results

    async def close_all(self) -> None:
        """Close all device clients and release connection pool resources."""
        for device_id, api_client in self.devices.items():
            try:
                await api_client.close()
                self.logger.info(f"Closed connection for device: {device_id}")
            except Exception as e:
                self.logger.error(f"Error closing connection for {device_id}: {e}")
