"""
doc.* MCP tools -- documentation/diagram generation over a device's live
configuration. Dotted taxonomy names become underscore-joined Python tool
names, matching the other tool modules (doc.generate_topology ->
doc_generate_topology).
"""
from __future__ import annotations

from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.documentation_service import DocumentationService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_doc_tools(mcp: FastMCP, documentation_service: DocumentationService) -> None:
    @mcp.tool(
        description=(
            "Generate a device topology diagram (interfaces, static routes, "
            "virtual IPs) in mermaid, drawio, or plantuml format."
        )
    )
    async def doc_generate_topology(
        device_id: _DeviceId,
        vdom: _Vdom = None,
        diagram_format: Annotated[
            str, Field(description="One of: mermaid, drawio, plantuml", default="mermaid")
        ] = "mermaid",
    ):
        return await documentation_service.generate_topology(device_id, vdom, diagram_format)

    @mcp.tool(description="Generate a Markdown table documenting all firewall policies.")
    async def doc_generate_policy_doc(device_id: _DeviceId, vdom: _Vdom = None):
        return await documentation_service.generate_policy_doc(device_id, vdom)

    @mcp.tool(description="Generate a Markdown document of static routes and the active routing table.")
    async def doc_generate_routing_doc(device_id: _DeviceId, vdom: _Vdom = None):
        return await documentation_service.generate_routing_doc(device_id, vdom)

    @mcp.tool(
        description=(
            "Generate a Markdown document of system configuration: DNS, NTP, "
            "syslog, SNMP (agent status + communities), admin accounts, HA, "
            "and global settings (hostname/timezone/admin ports)."
        )
    )
    async def doc_generate_system_config(device_id: _DeviceId, vdom: _Vdom = None):
        return await documentation_service.generate_system_config_doc(device_id, vdom)

    @mcp.tool(
        description=(
            "Export a combined Markdown report: device summary, system "
            "configuration, firewall policies, and routing, all in one document."
        )
    )
    async def doc_export_markdown(device_id: _DeviceId, vdom: _Vdom = None):
        return await documentation_service.export_markdown(device_id, vdom)

    @mcp.tool(
        description=(
            "Generate a Markdown document of VPN configuration: IPsec tunnels "
            "with live up/down status, phase2 traffic selectors, and SSL VPN "
            "settings/active session count."
        )
    )
    async def doc_generate_vpn_doc(device_id: _DeviceId, vdom: _Vdom = None):
        return await documentation_service.generate_vpn_doc(device_id, vdom)
