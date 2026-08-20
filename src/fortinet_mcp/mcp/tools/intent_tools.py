"""
intent.* MCP tools -- natural-language-shaped composites (Phase 7).
Claude does the actual language understanding (turning "create an HTTPS
policy from LAN to Internet" into structured fields); these tools do the
FortiGate-specific legwork of resolving those fields against live
configuration and delegating any mutation to the existing, already
change-engine-gated services.
"""
from __future__ import annotations

from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.intent_service import IntentService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_intent_tools(mcp: FastMCP, intent_service: IntentService) -> None:
    @mcp.tool(
        description=(
            "Create a firewall policy from high-level fields (e.g. 'HTTPS from "
            "LAN to Internet' -> source_zone='LAN', dest_zone='Internet', "
            "service='HTTPS'). Resolves zone/service names against the "
            "device's existing interfaces/service objects, falling back "
            "clearly-noted defaults when nothing matches, then proposes the "
            "policy through the same change engine as create_firewall_policy "
            "-- still requires change.apply(change_id) to actually create it."
        )
    )
    async def intent_create_policy(
        device_id: _DeviceId,
        name: Annotated[str, Field(description="Name for the new policy")],
        source_zone: Annotated[str, Field(description="Source zone/interface name, e.g. 'LAN'")],
        dest_zone: Annotated[str, Field(description="Destination zone/interface name, e.g. 'wan1'")],
        service: Annotated[str, Field(description="Service name, e.g. 'HTTPS'", default="ALL")] = "ALL",
        action: Annotated[str, Field(description="'accept' or 'deny'", default="accept")] = "accept",
        vdom: _Vdom = None,
    ):
        return await intent_service.create_policy(device_id, name, source_zone, dest_zone, service, action, vdom)

    @mcp.tool(
        description=(
            "Explain why a specific firewall policy might not be matching "
            "traffic as expected: checks whether it's disabled, shadowed by "
            "an earlier broader policy, schedule-restricted, or denied by an "
            "earlier deny rule. Configuration-level review only -- not a live "
            "session/traffic trace."
        )
    )
    async def intent_explain_policy_failure(
        device_id: _DeviceId,
        policy_id: Annotated[str, Field(description="The policy id to diagnose")],
        vdom: _Vdom = None,
    ):
        return await intent_service.explain_policy_failure(device_id, policy_id, vdom)

    @mcp.tool(
        description=(
            "Plain-English summary of a device: hostname, FortiOS version, "
            "interface up/down counts, policy/object counts, and its "
            "security score."
        )
    )
    async def intent_summarize_device(device_id: _DeviceId, vdom: _Vdom = None):
        return await intent_service.summarize_device(device_id, vdom)

    @mcp.tool(
        description=(
            "Simulate FortiGate's first-match-wins policy evaluation for one "
            "traffic tuple (source, destination address object names -- or "
            "'any' -- and an optional service name) and report which policy "
            "(if any) would handle it."
        )
    )
    async def intent_find_path(
        device_id: _DeviceId,
        source: Annotated[str, Field(description="Source address object name, or 'any'")],
        destination: Annotated[str, Field(description="Destination address object name, or 'any'")],
        service: Annotated[
            Optional[str], Field(description="Service name; omit to ignore service matching", default=None)
        ] = None,
        vdom: _Vdom = None,
    ):
        return await intent_service.find_path(device_id, source, destination, service, vdom)
