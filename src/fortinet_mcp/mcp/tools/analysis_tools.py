"""
analysis.* MCP tools -- read-only security/hygiene analysis over a
device's live configuration (Phase 4). Dotted taxonomy names become
underscore-joined Python tool names, matching the other tool modules
(analysis.find_any_any -> analysis_find_any_any).
"""
from __future__ import annotations

from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.analysis_service import AnalysisService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_analysis_tools(mcp: FastMCP, analysis_service: AnalysisService) -> None:
    @mcp.tool(
        description=(
            "Find firewall policies with identical match criteria and action "
            "-- fully redundant rules where removing either has no effect."
        )
    )
    async def analysis_find_duplicate_policies(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.find_duplicate_policies(device_id, vdom)

    @mcp.tool(
        description=(
            "Find firewall policies that can never match traffic because an "
            "earlier, broader enabled policy already matches everything they would."
        )
    )
    async def analysis_find_shadowed_policies(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.find_shadowed_policies(device_id, vdom)

    @mcp.tool(description="Find overly permissive any-source/any-destination/any-service policies.")
    async def analysis_find_any_any(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.find_any_any(device_id, vdom)

    @mcp.tool(
        description="Find address, service, and virtual IP objects not referenced by any firewall policy."
    )
    async def analysis_find_unused_objects(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.find_unused_objects(device_id, vdom)

    @mcp.tool(description="Find address objects whose subnets/ranges overlap with each other.")
    async def analysis_find_overlapping_subnets(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.find_overlapping_subnets(device_id, vdom)

    @mcp.tool(
        description=(
            "Check firewall policies against a set of Fortinet-style best-practice "
            "heuristics (traffic logging, comments, stale disabled rules)."
        )
    )
    async def analysis_check_best_practices(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.check_best_practices(device_id, vdom)

    @mcp.tool(
        description=(
            "Check device-level system configuration (DNS, NTP, syslog, SNMP "
            "communities, admin accounts, HA, hostname) against a set of "
            "best-practice heuristics -- the system.*/vdom.* counterpart to "
            "analysis_check_best_practices' policy checks."
        )
    )
    async def analysis_check_system_config(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.check_system_config(device_id, vdom)

    @mcp.tool(
        description=(
            "Compute a heuristic 0-100 security score for the device from the "
            "other analysis checks, including system configuration. Not an "
            "authoritative compliance measure -- a quick signal, not a certification."
        )
    )
    async def analysis_score_security(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.score_security(device_id, vdom)

    @mcp.tool(
        description=(
            "Generate a combined compliance report: security score plus every "
            "individual analysis finding, including system configuration checks."
        )
    )
    async def analysis_compliance_report(device_id: _DeviceId, vdom: _Vdom = None):
        return await analysis_service.compliance_report(device_id, vdom)
