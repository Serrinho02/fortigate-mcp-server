"""
New routing/topology MCP tools added in Phase C of the "configure a
FortiGate from zero" effort: interface CRUD (VLAN sub-interfaces, loopback,
vdom-link members -- not new physical ports, FortiOS doesn't allow that),
zones, and DHCP server. The pre-existing read-only interface/route tools
(list_interfaces, get_interface_status, list_static_routes, ...) are
registered elsewhere (server.py/server_http.py _setup_tools) and are not
duplicated here -- this module only adds what didn't exist before.
"""
from __future__ import annotations

from typing import Annotated, Any, Dict, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.routing_service import RoutingService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_routing_tools(mcp: FastMCP, routing_service: RoutingService) -> None:
    # --- Interfaces --------------------------------------------------------------

    @mcp.tool(
        description=(
            "Propose creating an interface (VLAN sub-interface, loopback, or "
            "a vdom-link member interface -- FortiOS does not allow creating "
            "new physical ports). Common fields: name, type (vlan/loopback), "
            "interface (parent), vlanid, ip, vdom, allowaccess. Returns a "
            "diff + change_id; call change.apply(change_id) to actually "
            "create it."
        )
    )
    async def routing_create_interface(
        device_id: _DeviceId,
        interface_data: Annotated[Dict[str, Any], Field(description="Interface fields, e.g. name/type/interface/vlanid/ip")],
        vdom: _Vdom = None,
    ):
        return await routing_service.create_interface(device_id, interface_data, vdom)

    @mcp.tool(
        description=(
            "Propose updating an interface (IP/netmask, role, VDOM "
            "assignment, allowed access, status). Returns a diff + change_id."
        )
    )
    async def routing_update_interface(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Interface name")],
        interface_data: Annotated[Dict[str, Any], Field(description="Interface fields to update")],
        vdom: _Vdom = None,
    ):
        return await routing_service.update_interface(device_id, name, interface_data, vdom)

    @mcp.tool(
        description=(
            "Propose deleting an interface. FortiOS rejects this for "
            "physical ports -- only VLAN/loopback/vdom-link member "
            "interfaces can actually be deleted. Returns a diff + change_id."
        )
    )
    async def routing_delete_interface(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Interface name")],
        vdom: _Vdom = None,
    ):
        return await routing_service.delete_interface(device_id, name, vdom)

    # --- Zones -------------------------------------------------------------------

    @mcp.tool(description="List zones (named interface groupings used by firewall policies).")
    async def routing_list_zones(device_id: _DeviceId, vdom: _Vdom = None):
        return await routing_service.list_zones(device_id, vdom)

    @mcp.tool(description="Propose creating a zone (name + member interfaces). Returns a diff + change_id.")
    async def routing_create_zone(
        device_id: _DeviceId,
        zone_data: Annotated[Dict[str, Any], Field(description="Zone fields, e.g. name/interface (member list)")],
        vdom: _Vdom = None,
    ):
        return await routing_service.create_zone(device_id, zone_data, vdom)

    @mcp.tool(description="Propose updating a zone's member interfaces. Returns a diff + change_id.")
    async def routing_update_zone(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Zone name")],
        zone_data: Annotated[Dict[str, Any], Field(description="Zone fields to update")],
        vdom: _Vdom = None,
    ):
        return await routing_service.update_zone(device_id, name, zone_data, vdom)

    @mcp.tool(description="Propose deleting a zone. Returns a diff + change_id.")
    async def routing_delete_zone(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Zone name")],
        vdom: _Vdom = None,
    ):
        return await routing_service.delete_zone(device_id, name, vdom)

    # --- DHCP server -------------------------------------------------------------

    @mcp.tool(description="List DHCP servers.")
    async def routing_list_dhcp_servers(device_id: _DeviceId, vdom: _Vdom = None):
        return await routing_service.list_dhcp_servers(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose creating a DHCP server (interface, ip-range, netmask, "
            "default-gateway, dns-server1, ...). Returns a diff + change_id."
        )
    )
    async def routing_create_dhcp_server(
        device_id: _DeviceId,
        server_data: Annotated[Dict[str, Any], Field(description="DHCP server fields, e.g. interface/ip-range/netmask")],
        vdom: _Vdom = None,
    ):
        return await routing_service.create_dhcp_server(device_id, server_data, vdom)

    @mcp.tool(description="Propose updating a DHCP server. Returns a diff + change_id.")
    async def routing_update_dhcp_server(
        device_id: _DeviceId,
        server_id: Annotated[str, Field(description="DHCP server id")],
        server_data: Annotated[Dict[str, Any], Field(description="DHCP server fields to update")],
        vdom: _Vdom = None,
    ):
        return await routing_service.update_dhcp_server(device_id, server_id, server_data, vdom)

    @mcp.tool(description="Propose deleting a DHCP server. Returns a diff + change_id.")
    async def routing_delete_dhcp_server(
        device_id: _DeviceId,
        server_id: Annotated[str, Field(description="DHCP server id")],
        vdom: _Vdom = None,
    ):
        return await routing_service.delete_dhcp_server(device_id, server_id, vdom)
