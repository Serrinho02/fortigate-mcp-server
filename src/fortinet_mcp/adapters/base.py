"""
The plugin boundary: `FortinetProductAdapter` is the only contract that
services, domain engines, and repositories depend on. A Fortinet product
(FortiOS today; FortiManager, FortiWeb, ... later) is supported by writing
one adapter class that implements this Protocol — no other layer changes.

Phase 0 scope: the Protocol mirrors today's FortiGateAPI operations 1:1 in
canonical verb form (list/get/create/update/delete per resource), still
returning raw vendor JSON as `dict[str, Any]`. Canonical typed domain models
(Policy, AddressObject, ...) replace these raw dicts in a later phase once
`domain/models.py` exists — this Protocol's shape is expected to evolve then,
not before.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


class Capability(str, Enum):
    """A unit of functionality an adapter may or may not support.

    Services use `adapter.capabilities()` to degrade gracefully instead of
    calling a method that would raise NotImplementedError — e.g. a future
    product without virtual IPs simply omits VIRTUAL_IP from its set.
    """

    SYSTEM_STATUS = "system_status"
    VDOM = "vdom"
    INTERFACE = "interface"
    FIREWALL_POLICY = "firewall_policy"
    ADDRESS_OBJECT = "address_object"
    SERVICE_OBJECT = "service_object"
    STATIC_ROUTE = "static_route"
    VIRTUAL_IP = "virtual_ip"
    IPSEC_VPN = "ipsec_vpn"
    SSL_VPN = "ssl_vpn"
    DNS = "dns"
    NTP = "ntp"
    SYSLOG = "syslog"
    SNMP = "snmp"
    SYSTEM_GLOBAL = "system_global"
    ADMIN = "admin"
    HA = "ha"
    VDOM_LIFECYCLE = "vdom_lifecycle"
    ZONE = "zone"
    DHCP_SERVER = "dhcp_server"


@runtime_checkable
class FortinetProductAdapter(Protocol):
    """Canonical operations every Fortinet product adapter must expose."""

    product_type: str

    def capabilities(self) -> frozenset[Capability]:
        """Which `Capability` values this adapter instance supports."""
        ...

    async def test_connection(self) -> bool:
        """Lightweight reachability/auth check, used by health probes."""
        ...

    async def close(self) -> None:
        """Release any underlying connection/session resources."""
        ...

    # --- System / VDOM / interfaces ---------------------------------------

    async def get_status(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def list_vdoms(self) -> dict[str, Any]: ...

    # --- VDOM lifecycle + inter-VDOM links -------------------------------------
    # `vdom` kwargs below are accepted-but-ignored: VDOM/vdom-link objects are
    # global (not scoped to a VDOM themselves), but change_dispatch's generic
    # execute()/fetch_current() always pass vdom=... to every resource type's
    # methods, so the signature must accept it for these to be dispatchable
    # like every other keyed resource.

    async def create_vdom(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_vdom(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def list_vdom_links(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_vdom_link(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_vdom_link(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_vdom_link(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def list_interfaces(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_interface_status(
        self, interface_name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def get_interface(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_interface(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_interface(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_interface(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- Zones -----------------------------------------------------------------

    async def list_zones(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_zone(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_zone(self, data: dict[str, Any], vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_zone(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_zone(self, name: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- DHCP server -------------------------------------------------------------

    async def list_dhcp_servers(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_dhcp_server(self, server_id: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_dhcp_server(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_dhcp_server(
        self, server_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_dhcp_server(self, server_id: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- Firewall policy -----------------------------------------------------

    async def list_policies(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_policy(
        self, policy_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def create_policy(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_policy(
        self, policy_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_policy(
        self, policy_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- Address objects -----------------------------------------------------

    async def list_address_objects(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_address_object(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_address_object(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_address_object(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- Service objects -----------------------------------------------------

    async def list_service_objects(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_service_object(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_service_object(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_service_object(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- Static routes ---------------------------------------------------

    async def list_static_routes(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_static_route(
        self, route_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def create_static_route(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_static_route(
        self, route_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_static_route(
        self, route_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def get_routing_table(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- Virtual IPs -----------------------------------------------------

    async def list_virtual_ips(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_virtual_ip(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def create_virtual_ip(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_virtual_ip(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_virtual_ip(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- IPsec VPN (phase1 = tunnel/gateway, phase2 = traffic selector) -----

    async def list_ipsec_phase1(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_ipsec_phase1(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def create_ipsec_phase1(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_ipsec_phase1(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_ipsec_phase1(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def list_ipsec_phase2(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_ipsec_phase2(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def create_ipsec_phase2(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_ipsec_phase2(
        self, name: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_ipsec_phase2(
        self, name: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def get_ipsec_tunnel_status(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- SSL VPN -----------------------------------------------------------

    async def get_ssl_vpn_settings(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_ssl_vpn_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def get_ssl_vpn_sessions(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- DNS (singleton) -----------------------------------------------------

    async def get_dns_settings(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_dns_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- NTP (singleton, global) ---------------------------------------------

    async def get_ntp_settings(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_ntp_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- Syslog (singleton) ---------------------------------------------------

    async def get_syslog_settings(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_syslog_settings(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- SNMP (sysinfo singleton, community keyed) -- global -----------------

    async def get_snmp_sysinfo(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_snmp_sysinfo(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def list_snmp_communities(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_snmp_community(
        self, community_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def create_snmp_community(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_snmp_community(
        self, community_id: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_snmp_community(
        self, community_id: str, vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- System global settings (singleton, global) ---------------------------

    async def get_system_global(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_system_global(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    # --- Admin users (keyed by username, global) -------------------------------

    async def list_admins(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def get_admin(self, username: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def create_admin(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def update_admin(
        self, username: str, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...

    async def delete_admin(self, username: str, vdom: Optional[str] = None) -> dict[str, Any]: ...

    # --- HA configuration (singleton, global) ----------------------------------

    async def get_ha_config(self, vdom: Optional[str] = None) -> dict[str, Any]: ...

    async def update_ha_config(
        self, data: dict[str, Any], vdom: Optional[str] = None
    ) -> dict[str, Any]: ...
