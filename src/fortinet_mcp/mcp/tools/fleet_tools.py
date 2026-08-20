"""
fleet.* MCP tools -- multi-device operations across the inventory (Phase
6). Dotted taxonomy names become underscore-joined Python tool names
(fleet.compare_devices -> fleet_compare_devices). Targets are resolved the
same way as connection.connect: a device name, site name, customer name,
or management IP.
"""
from __future__ import annotations

from typing import Annotated, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.fleet_service import FleetService

_ResourceType = Annotated[
    str,
    Field(
        description=(
            "One of: firewall_policy, address_object, service_object, static_route, virtual_ip"
        )
    ),
]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_fleet_tools(mcp: FastMCP, fleet_service: FleetService) -> None:
    @mcp.tool(
        description=(
            "Compare a resource type (default: firewall_policy) between two "
            "devices -- what's only on one side, what's identical, and what "
            "differs field-by-field."
        )
    )
    async def fleet_compare_devices(
        target_a: Annotated[str, Field(description="First device: name, site, customer, or IP")],
        target_b: Annotated[str, Field(description="Second device: name, site, customer, or IP")],
        resource_type: _ResourceType = "firewall_policy",
        vdom: _Vdom = None,
    ):
        return await fleet_service.compare_devices(target_a, target_b, resource_type, vdom)

    @mcp.tool(
        description=(
            "Search for an object (by name, or policy id for firewall_policy) "
            "across every device matched by target -- or the entire inventory "
            "if target is omitted."
        )
    )
    async def fleet_search_object(
        object_name: Annotated[str, Field(description="Object name (or policy id) to search for")],
        resource_type: _ResourceType = "address_object",
        target: Annotated[
            Optional[str],
            Field(description="Scope: device/site/customer name or IP; omit to search everything", default=None),
        ] = None,
        vdom: _Vdom = None,
    ):
        return await fleet_service.search_object(object_name, resource_type, target, vdom)

    @mcp.tool(
        description=(
            "Copy objects present on a source device but missing on a "
            "destination device. Without confirm=True, only returns the plan "
            "(what would be created) -- nothing is written. Pass confirm=True "
            "to actually execute; still blocked by READ_ONLY/SAFE mode."
        )
    )
    async def fleet_sync_objects(
        source_target: Annotated[str, Field(description="Source device: name, site, customer, or IP")],
        dest_target: Annotated[str, Field(description="Destination device: name, site, customer, or IP")],
        resource_type: _ResourceType = "address_object",
        vdom: _Vdom = None,
        confirm: Annotated[
            bool, Field(description="Set true to actually execute (default: dry-run plan only)", default=False)
        ] = False,
    ):
        return await fleet_service.sync_objects(source_target, dest_target, resource_type, vdom, confirm)

    @mcp.tool(
        description=(
            "Like fleet.sync_objects, but for multiple resource types (default: "
            "address + service objects) replicated from one source device to "
            "every device matched by dest_target (e.g. an entire site). "
            "Without confirm=True, only returns the plan."
        )
    )
    async def fleet_replicate_config(
        source_target: Annotated[str, Field(description="Source device: name, site, customer, or IP")],
        dest_target: Annotated[
            str, Field(description="Destination scope: device/site/customer name or IP (may match many devices)")
        ],
        resource_types: Annotated[
            Optional[List[str]],
            Field(description="Resource types to replicate; default address_object + service_object", default=None),
        ] = None,
        vdom: _Vdom = None,
        confirm: Annotated[
            bool, Field(description="Set true to actually execute (default: dry-run plan only)", default=False)
        ] = False,
    ):
        return await fleet_service.replicate_config(source_target, dest_target, resource_types, vdom, confirm)

    @mcp.tool(
        description=(
            "Generate a fleet-wide security report: per-device security "
            "score plus a fleet summary, for every device matched by target "
            "(e.g. a whole customer or site)."
        )
    )
    async def fleet_report(
        target: Annotated[str, Field(description="Device, site, or customer name (or IP)")],
        vdom: _Vdom = None,
    ):
        return await fleet_service.report(target, vdom)
