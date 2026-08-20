"""
`FortiOSAdapter` — thin delegate wrapping the existing `FortiGateAPI` client.

Phase 0 scope: this is a shim, not a rewrite. It performs zero data
transformation and changes zero behavior versus calling `FortiGateAPI`
directly — its only job is to prove that FortiOS fits the
`FortinetProductAdapter` Protocol shape so the layers above it (built in
later phases) never need to import FortiOS-specific types. The real HTTP
client migrates out of `fortigate_mcp.core.fortigate` and into
`adapters/fortios/client.py` in Phase 2; until then this adapter simply
wraps the pre-existing client in place.
"""
from __future__ import annotations

from typing import Any, Optional

from src.fortigate_mcp.core.fortigate import FortiGateAPI

from ..base import Capability

_ALL_CAPABILITIES = frozenset(
    {
        Capability.SYSTEM_STATUS,
        Capability.VDOM,
        Capability.INTERFACE,
        Capability.FIREWALL_POLICY,
        Capability.ADDRESS_OBJECT,
        Capability.SERVICE_OBJECT,
        Capability.STATIC_ROUTE,
        Capability.VIRTUAL_IP,
        Capability.IPSEC_VPN,
        Capability.SSL_VPN,
        Capability.DNS,
        Capability.NTP,
        Capability.SYSLOG,
        Capability.SNMP,
        Capability.SYSTEM_GLOBAL,
        Capability.ADMIN,
        Capability.HA,
        Capability.VDOM_LIFECYCLE,
        Capability.ZONE,
        Capability.DHCP_SERVER,
    }
)


class FortiOSAdapter:
    """Adapts a `FortiGateAPI` client to the `FortinetProductAdapter` Protocol."""

    product_type = "fortios"

    def __init__(self, client: FortiGateAPI):
        self._client = client

    def capabilities(self) -> frozenset[Capability]:
        return _ALL_CAPABILITIES

    async def test_connection(self) -> bool:
        return await self._client.test_connection()

    async def close(self) -> None:
        await self._client.close()

    # --- System / VDOM / interfaces ---------------------------------------

    async def get_status(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_system_status(vdom=vdom)

    async def list_vdoms(self) -> dict[str, Any]:
        return await self._client.get_vdoms()

    # --- VDOM lifecycle + inter-VDOM links (vdom kwarg accepted-but-ignored,
    # see adapters/base.py Protocol docstring) --------------------------------

    async def create_vdom(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_vdom(data)

    async def delete_vdom(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.delete_vdom(name)

    async def list_vdom_links(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_vdom_links()

    async def get_vdom_link(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_vdom_link_detail(name)

    async def create_vdom_link(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_vdom_link(data)

    async def delete_vdom_link(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.delete_vdom_link(name)

    async def list_interfaces(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_interfaces(vdom=vdom)

    async def get_interface_status(
        self, interface_name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_interface_status(interface_name, vdom=vdom)

    async def get_interface(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_interface_detail(name, vdom=vdom)

    async def create_interface(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_interface(data, vdom=vdom)

    async def update_interface(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_interface(name, data, vdom=vdom)

    async def delete_interface(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.delete_interface(name, vdom=vdom)

    # --- Zones -----------------------------------------------------------------

    async def list_zones(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_zones(vdom=vdom)

    async def get_zone(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_zone_detail(name, vdom=vdom)

    async def create_zone(self, data: dict[str, Any], vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.create_zone(data, vdom=vdom)

    async def update_zone(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_zone(name, data, vdom=vdom)

    async def delete_zone(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.delete_zone(name, vdom=vdom)

    # --- DHCP server -------------------------------------------------------------

    async def list_dhcp_servers(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_dhcp_servers(vdom=vdom)

    async def get_dhcp_server(self, server_id: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_dhcp_server_detail(server_id, vdom=vdom)

    async def create_dhcp_server(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_dhcp_server(data, vdom=vdom)

    async def update_dhcp_server(
        self, server_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_dhcp_server(server_id, data, vdom=vdom)

    async def delete_dhcp_server(self, server_id: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.delete_dhcp_server(server_id, vdom=vdom)

    # --- Firewall policy -----------------------------------------------------

    async def list_policies(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_firewall_policies(vdom=vdom)

    async def get_policy(
        self, policy_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_firewall_policy_detail(policy_id, vdom=vdom)

    async def create_policy(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_firewall_policy(data, vdom=vdom)

    async def update_policy(
        self, policy_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_firewall_policy(policy_id, data, vdom=vdom)

    async def delete_policy(
        self, policy_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_firewall_policy(policy_id, vdom=vdom)

    # --- Address objects -----------------------------------------------------

    async def list_address_objects(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_address_objects(vdom=vdom)

    async def create_address_object(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_address_object(data, vdom=vdom)

    async def update_address_object(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_address_object(name, data, vdom=vdom)

    async def delete_address_object(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_address_object(name, vdom=vdom)

    # --- Service objects -----------------------------------------------------

    async def list_service_objects(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_service_objects(vdom=vdom)

    async def create_service_object(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_service_object(data, vdom=vdom)

    async def update_service_object(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_service_object(name, data, vdom=vdom)

    async def delete_service_object(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_service_object(name, vdom=vdom)

    # --- Static routes ---------------------------------------------------

    async def list_static_routes(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_static_routes(vdom=vdom)

    async def get_static_route(
        self, route_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_static_route_detail(route_id, vdom=vdom)

    async def create_static_route(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_static_route(data, vdom=vdom)

    async def update_static_route(
        self, route_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_static_route(route_id, data, vdom=vdom)

    async def delete_static_route(
        self, route_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_static_route(route_id, vdom=vdom)

    async def get_routing_table(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_routing_table(vdom=vdom)

    # --- Virtual IPs -----------------------------------------------------

    async def list_virtual_ips(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_virtual_ips(vdom=vdom)

    async def get_virtual_ip(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_virtual_ip_detail(name, vdom=vdom)

    async def create_virtual_ip(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_virtual_ip(data, vdom=vdom)

    async def update_virtual_ip(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_virtual_ip(name, data, vdom=vdom)

    async def delete_virtual_ip(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_virtual_ip(name, vdom=vdom)

    # --- IPsec VPN -----------------------------------------------------

    async def list_ipsec_phase1(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ipsec_phase1_list(vdom=vdom)

    async def get_ipsec_phase1(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_ipsec_phase1_detail(name, vdom=vdom)

    async def create_ipsec_phase1(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_ipsec_phase1(data, vdom=vdom)

    async def update_ipsec_phase1(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_ipsec_phase1(name, data, vdom=vdom)

    async def delete_ipsec_phase1(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_ipsec_phase1(name, vdom=vdom)

    async def list_ipsec_phase2(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ipsec_phase2_list(vdom=vdom)

    async def get_ipsec_phase2(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_ipsec_phase2_detail(name, vdom=vdom)

    async def create_ipsec_phase2(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_ipsec_phase2(data, vdom=vdom)

    async def update_ipsec_phase2(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_ipsec_phase2(name, data, vdom=vdom)

    async def delete_ipsec_phase2(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_ipsec_phase2(name, vdom=vdom)

    async def get_ipsec_tunnel_status(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ipsec_tunnel_status(vdom=vdom)

    # --- SSL VPN -----------------------------------------------------------

    async def get_ssl_vpn_settings(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ssl_vpn_settings(vdom=vdom)

    async def update_ssl_vpn_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_ssl_vpn_settings(data, vdom=vdom)

    async def get_ssl_vpn_sessions(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ssl_vpn_sessions(vdom=vdom)

    # --- DNS -----------------------------------------------------------------

    async def get_dns_settings(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_dns_settings(vdom=vdom)

    async def update_dns_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_dns_settings(data, vdom=vdom)

    # --- NTP -----------------------------------------------------------------

    async def get_ntp_settings(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ntp_settings(vdom=vdom)

    async def update_ntp_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_ntp_settings(data, vdom=vdom)

    # --- Syslog ----------------------------------------------------------------

    async def get_syslog_settings(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_syslog_settings(vdom=vdom)

    async def update_syslog_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_syslog_settings(data, vdom=vdom)

    # --- SNMP ------------------------------------------------------------------

    async def get_snmp_sysinfo(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_snmp_sysinfo(vdom=vdom)

    async def update_snmp_sysinfo(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_snmp_sysinfo(data, vdom=vdom)

    async def list_snmp_communities(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_snmp_communities(vdom=vdom)

    async def get_snmp_community(
        self, community_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.get_snmp_community_detail(community_id, vdom=vdom)

    async def create_snmp_community(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_snmp_community(data, vdom=vdom)

    async def update_snmp_community(
        self, community_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_snmp_community(community_id, data, vdom=vdom)

    async def delete_snmp_community(
        self, community_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.delete_snmp_community(community_id, vdom=vdom)

    # --- System global settings -------------------------------------------------

    async def get_system_global(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_system_global(vdom=vdom)

    async def update_system_global(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_system_global(data, vdom=vdom)

    # --- Admin users -------------------------------------------------------------

    async def list_admins(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.list_admins(vdom=vdom)

    async def get_admin(self, username: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_admin_detail(username, vdom=vdom)

    async def create_admin(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.create_admin(data, vdom=vdom)

    async def update_admin(
        self, username: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_admin(username, data, vdom=vdom)

    async def delete_admin(self, username: str, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.delete_admin(username, vdom=vdom)

    # --- HA configuration --------------------------------------------------------

    async def get_ha_config(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return await self._client.get_ha_config(vdom=vdom)

    async def update_ha_config(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]:
        return await self._client.update_ha_config(data, vdom=vdom)
