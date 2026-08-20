"""
connection.* MCP tools -- resolve a free-form target string ("Milano",
"customer Alfa", "10.10.10.1") to a device and manage its live session,
backed by ConnectionManager. Claude never supplies an IP to *connect*
with in the old sense -- it names a device/site/customer and the manager
resolves it against the inventory DB.
"""
from __future__ import annotations

from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...errors import (
    AmbiguousTargetError,
    CredentialNotProvisionedError,
    DeviceConnectionError,
    DeviceNotFoundError,
)
from ...infra.connection_manager import ConnectionManager, ConnectionSession


def _session_to_dict(session: ConnectionSession) -> dict:
    return {
        "device_id": session.device_id,
        "vdom": session.vdom,
        "customer": session.customer_name,
        "site": session.site_name,
        "device": session.device_name,
        "mgmt_host": session.mgmt_host,
        "product_type": session.product_type,
        "model": session.model,
        "serial": session.serial,
        "fortios_version": session.fortios_version,
        "ha_role": session.ha_role,
        "state": session.state,
    }


def register_connection_tools(mcp: FastMCP, connection_manager: ConnectionManager) -> None:
    @mcp.tool(
        description=(
            "Connect to a firewall by name, site, customer, or management IP "
            "(e.g. 'Milano', 'Alfa', '10.10.10.1'). Reuses an existing "
            "connection if one is already open. If the target matches "
            "multiple devices (e.g. a customer or site with several "
            "firewalls), the error lists the candidates -- pick one and "
            "call again."
        )
    )
    async def connection_connect(
        target: Annotated[
            str, Field(description="Device name, site name, customer name, or management IP")
        ],
        vdom: Annotated[
            Optional[str],
            Field(description="VDOM to use (defaults to the device's default VDOM)", default=None),
        ] = None,
    ):
        try:
            session = await connection_manager.connect(target, vdom=vdom)
        except (
            ValueError,
            AmbiguousTargetError,
            DeviceNotFoundError,
            CredentialNotProvisionedError,
            DeviceConnectionError,
        ) as e:
            return {"error": str(e)}
        return _session_to_dict(session)

    @mcp.tool(description="List currently open (cached) device connections.")
    async def connection_list_active():
        return [_session_to_dict(s) for s in connection_manager.list_active()]

    @mcp.tool(
        description=(
            "Resolve a target string to the matching device(s) without "
            "connecting -- useful to check for ambiguity before "
            "connection.connect."
        )
    )
    async def connection_resolve(
        target: Annotated[
            str, Field(description="Device name, site name, customer name, or management IP")
        ],
    ):
        try:
            devices = await connection_manager.resolve_target(target)
        except (ValueError, AmbiguousTargetError, DeviceNotFoundError) as e:
            return {"error": str(e)}
        return [
            {
                "device_id": d.id,
                "name": d.name,
                "site": d.site.name,
                "customer": d.site.customer.name,
                "mgmt_host": d.mgmt_host,
            }
            for d in devices
        ]

    @mcp.tool(
        description="Disconnect a device (target resolved the same way as connection.connect)."
    )
    async def connection_disconnect(
        target: Annotated[
            str, Field(description="Device name, site name, customer name, or management IP")
        ],
        vdom: Annotated[
            Optional[str], Field(description="Limit to this VDOM only", default=None)
        ] = None,
    ):
        try:
            devices = await connection_manager.resolve_target(target)
        except (ValueError, AmbiguousTargetError, DeviceNotFoundError) as e:
            return {"error": str(e)}
        for device in devices:
            await connection_manager.disconnect(device.id, vdom=vdom)
        return {"disconnected": [d.id for d in devices]}
