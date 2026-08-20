"""
vpn.* MCP tools -- IPsec VPN tunnel management plus read-only IPsec/SSL
VPN status visibility. Dotted taxonomy names become underscore-joined
Python tool names, matching the other tool modules (vpn.create_ipsec_tunnel
-> vpn_create_ipsec_tunnel).

Security note: an IPsec tunnel's pre-shared key (psksecret) is a normal
tool argument here, not routed through the OS keyring like FortiGate
device credentials are -- it will be visible in the conversation/tool-call
history. FortiGate's own API never returns it in GET responses (it's
write-only), so there's nothing this server could redact on the read
path, but be aware of this on the write path.
"""
from __future__ import annotations

from typing import Annotated, Any, Dict, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.vpn_service import VpnService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_vpn_tools(mcp: FastMCP, vpn_service: VpnService) -> None:
    @mcp.tool(description="List IPsec VPN tunnels (phase1-interface definitions).")
    async def vpn_list_ipsec_tunnels(device_id: _DeviceId, vdom: _Vdom = None):
        return await vpn_service.list_ipsec_tunnels(device_id, vdom)

    @mcp.tool(description="Get detailed configuration for a specific IPsec tunnel.")
    async def vpn_get_ipsec_tunnel_detail(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Tunnel name")],
        vdom: _Vdom = None,
    ):
        return await vpn_service.get_ipsec_tunnel_detail(device_id, name, vdom)

    @mcp.tool(
        description=(
            "Propose creating an IPsec site-to-site VPN tunnel (phase1-interface: "
            "remote gateway, outgoing interface, auth method/PSK, IKE version, "
            "proposal). Note: psksecret is a normal argument here and will be "
            "visible in the conversation -- FortiGate never returns it on GET, "
            "so there's no read-side leak, but be mindful on write. Returns a "
            "diff + change_id; call change.apply(change_id) to actually create it. "
            "A working tunnel also needs at least one phase2 selector -- see "
            "vpn_create_ipsec_phase2."
        )
    )
    async def vpn_create_ipsec_tunnel(
        device_id: _DeviceId,
        tunnel_data: Annotated[
            Dict[str, Any],
            Field(description="Phase1-interface fields, e.g. name/interface/remote-gw/psksecret"),
        ],
        vdom: _Vdom = None,
    ):
        return await vpn_service.create_ipsec_tunnel(device_id, tunnel_data, vdom)

    @mcp.tool(
        description="Propose updating an existing IPsec tunnel's phase1 configuration. Returns a diff + change_id."
    )
    async def vpn_update_ipsec_tunnel(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Tunnel name")],
        tunnel_data: Annotated[Dict[str, Any], Field(description="Phase1-interface fields to update")],
        vdom: _Vdom = None,
    ):
        return await vpn_service.update_ipsec_tunnel(device_id, name, tunnel_data, vdom)

    @mcp.tool(
        description="Propose deleting an IPsec tunnel (phase1-interface). Returns a diff + change_id."
    )
    async def vpn_delete_ipsec_tunnel(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Tunnel name")],
        vdom: _Vdom = None,
    ):
        return await vpn_service.delete_ipsec_tunnel(device_id, name, vdom)

    @mcp.tool(description="List IPsec phase2 traffic selectors (the subnets that pass through a tunnel).")
    async def vpn_list_ipsec_phase2(device_id: _DeviceId, vdom: _Vdom = None):
        return await vpn_service.list_ipsec_phase2(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose creating an IPsec phase2 traffic selector, linked to an "
            "existing tunnel by phase1name. Required for traffic to actually "
            "flow through a site-to-site VPN. Returns a diff + change_id."
        )
    )
    async def vpn_create_ipsec_phase2(
        device_id: _DeviceId,
        phase2_data: Annotated[
            Dict[str, Any], Field(description="Phase2-interface fields, e.g. name/phase1name/src-subnet/dst-subnet")
        ],
        vdom: _Vdom = None,
    ):
        return await vpn_service.create_ipsec_phase2(device_id, phase2_data, vdom)

    @mcp.tool(description="Propose updating an IPsec phase2 traffic selector. Returns a diff + change_id.")
    async def vpn_update_ipsec_phase2(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Phase2 selector name")],
        phase2_data: Annotated[Dict[str, Any], Field(description="Phase2-interface fields to update")],
        vdom: _Vdom = None,
    ):
        return await vpn_service.update_ipsec_phase2(device_id, name, phase2_data, vdom)

    @mcp.tool(description="Propose deleting an IPsec phase2 traffic selector. Returns a diff + change_id.")
    async def vpn_delete_ipsec_phase2(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Phase2 selector name")],
        vdom: _Vdom = None,
    ):
        return await vpn_service.delete_ipsec_phase2(device_id, name, vdom)

    @mcp.tool(description="Get live IPsec tunnel status (up/down, traffic counters).")
    async def vpn_get_ipsec_status(device_id: _DeviceId, vdom: _Vdom = None):
        return await vpn_service.get_ipsec_status(device_id, vdom)

    @mcp.tool(description="Get SSL VPN settings (port, source interface, tunnel IP pools). Read-only.")
    async def vpn_get_ssl_vpn_settings(device_id: _DeviceId, vdom: _Vdom = None):
        return await vpn_service.get_ssl_vpn_settings(device_id, vdom)

    @mcp.tool(description="List active SSL VPN sessions (connected remote users). Read-only.")
    async def vpn_list_ssl_vpn_sessions(device_id: _DeviceId, vdom: _Vdom = None):
        return await vpn_service.list_ssl_vpn_sessions(device_id, vdom)
