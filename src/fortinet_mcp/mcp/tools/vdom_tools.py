"""
vdom.* MCP tools -- VDOM lifecycle (create/delete) and inter-VDOM links.
Dotted taxonomy names become underscore-joined Python tool names, matching
the other tool modules (vdom.create -> vdom_create).

VDOM listing itself is discover_vdoms (registered elsewhere, DeviceService) --
not duplicated here. See services/vdom_service.py for why none of these
tools take a `vdom` parameter (VDOM and vdom-link objects are global, not
scoped to any one VDOM).
"""
from __future__ import annotations

from typing import Annotated, Any, Dict

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.vdom_service import VdomService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]


def register_vdom_tools(mcp: FastMCP, vdom_service: VdomService) -> None:
    @mcp.tool(
        description=(
            "Propose creating a new VDOM. WARNING: the device must already be "
            "in multi-vdom mode -- if discover_vdoms shows only 'root', first "
            "call system_update_global with vdom-mode: multi-vdom (see "
            "system_tools.py) and apply that change. Enabling multi-vdom mode "
            "for the first time can require a reboot or briefly disrupt "
            "management connectivity depending on the device/firmware -- "
            "verify this against the target device rather than assuming. "
            "Returns a diff + change_id; call change.apply(change_id) to "
            "actually create it."
        )
    )
    async def vdom_create(
        device_id: _DeviceId,
        vdom_data: Annotated[Dict[str, Any], Field(description="VDOM fields, e.g. name")],
    ):
        return await vdom_service.create_vdom(device_id, vdom_data)

    @mcp.tool(
        description=(
            "Propose deleting a VDOM. All interfaces/policies/objects "
            "assigned to it must be moved or removed first, or FortiOS will "
            "reject the deletion. Returns a diff + change_id."
        )
    )
    async def vdom_delete(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="VDOM name")],
    ):
        return await vdom_service.delete_vdom(device_id, name)

    @mcp.tool(description="List inter-VDOM links (virtual interface pairs joining two VDOMs).")
    async def vdom_list_links(device_id: _DeviceId):
        return await vdom_service.list_vdom_links(device_id)

    @mcp.tool(
        description=(
            "Propose creating an inter-VDOM link. FortiOS creates a pair of "
            "virtual interfaces (<name>0/<name>1); each side must then be "
            "assigned to one of the two VDOMs being joined via "
            "create_interface/update_interface (interface tools). Returns a "
            "diff + change_id."
        )
    )
    async def vdom_create_link(
        device_id: _DeviceId,
        link_data: Annotated[Dict[str, Any], Field(description="vdom-link fields, e.g. name")],
    ):
        return await vdom_service.create_vdom_link(device_id, link_data)

    @mcp.tool(description="Propose deleting an inter-VDOM link. Returns a diff + change_id.")
    async def vdom_delete_link(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="vdom-link name")],
    ):
        return await vdom_service.delete_vdom_link(device_id, name)
