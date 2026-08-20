"""
DocumentationService -- read-only documentation/diagram generation over a
device's live configuration. Every method only issues GET-shaped adapter
calls; nothing routes through ChangeService because nothing here mutates
state.
"""
from __future__ import annotations

from typing import List, Optional

from mcp.types import TextContent as Content

from ..docsgen import drawio, markdown, mermaid, plantuml
from . import change_dispatch
from .base import FortiGateServiceBase, service_operation

_TOPOLOGY_GENERATORS = {
    "mermaid": mermaid.generate_topology,
    "drawio": drawio.generate_topology,
    "plantuml": plantuml.generate_topology,
}


class DocumentationService(FortiGateServiceBase):
    async def _fetch_system_config(self, device_id: str, vdom: Optional[str]) -> dict:
        """Best-effort, same shape/rationale as AnalysisService's helper of
        the same name: a future non-FortiOS adapter might not implement
        every one of these, so each field degrades to empty/missing rather
        than failing the whole document."""
        adapter = await self._get_adapter(device_id)

        async def _safe_single(coro):
            try:
                return change_dispatch.unwrap_single(await coro) or {}
            except Exception:
                return {}

        async def _safe_list(coro):
            try:
                return change_dispatch.unwrap_list(await coro)
            except Exception:
                return []

        return {
            "dns": await _safe_single(adapter.get_dns_settings(vdom=vdom)),
            "ntp": await _safe_single(adapter.get_ntp_settings(vdom=vdom)),
            "syslog": await _safe_single(adapter.get_syslog_settings(vdom=vdom)),
            "snmp_sysinfo": await _safe_single(adapter.get_snmp_sysinfo(vdom=vdom)),
            "snmp_communities": await _safe_list(adapter.list_snmp_communities(vdom=vdom)),
            "admins": await _safe_list(adapter.list_admins(vdom=vdom)),
            "ha": await _safe_single(adapter.get_ha_config(vdom=vdom)),
            "global_settings": await _safe_single(adapter.get_system_global(vdom=vdom)),
        }

    @service_operation("generate topology diagram")
    async def generate_topology(
        self,
        device_id: str,
        vdom: Optional[str] = None,
        diagram_format: str = "mermaid",
    ) -> List[Content]:
        if diagram_format not in _TOPOLOGY_GENERATORS:
            raise ValueError(
                f"Unknown diagram_format '{diagram_format}'. "
                f"Expected one of: {', '.join(sorted(_TOPOLOGY_GENERATORS))}"
            )

        adapter = await self._get_adapter(device_id)
        interfaces = change_dispatch.unwrap_list(await adapter.list_interfaces(vdom=vdom))
        static_routes = change_dispatch.unwrap_list(await adapter.list_static_routes(vdom=vdom))
        vips = change_dispatch.unwrap_list(await adapter.list_virtual_ips(vdom=vdom))

        generate = _TOPOLOGY_GENERATORS[diagram_format]
        content = generate(device_id, interfaces, static_routes, vips)
        return self._format_document(content)

    @service_operation("generate policy documentation")
    async def generate_policy_doc(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        policies = change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))
        content = markdown.generate_policy_doc(device_id, policies)
        return self._format_document(content)

    @service_operation("generate routing documentation")
    async def generate_routing_doc(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        static_routes = change_dispatch.unwrap_list(await adapter.list_static_routes(vdom=vdom))
        routing_table = change_dispatch.unwrap_list(await adapter.get_routing_table(vdom=vdom))
        content = markdown.generate_routing_doc(device_id, static_routes, routing_table)
        return self._format_document(content)

    @service_operation("export markdown")
    async def export_markdown(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """The combined report: device summary + system config + policy doc
        + routing doc in one Markdown document."""
        adapter = await self._get_adapter(device_id)

        status = (change_dispatch.unwrap_single(await adapter.get_status(vdom=vdom)) or {})
        interfaces = change_dispatch.unwrap_list(await adapter.list_interfaces(vdom=vdom))
        vdoms = change_dispatch.unwrap_list(await adapter.list_vdoms())
        policies = change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))
        static_routes = change_dispatch.unwrap_list(await adapter.list_static_routes(vdom=vdom))
        routing_table = change_dispatch.unwrap_list(await adapter.get_routing_table(vdom=vdom))
        system_config_bundle = await self._fetch_system_config(device_id, vdom)

        sections = [
            markdown.generate_device_doc(device_id, status=status, interfaces=interfaces, vdoms=vdoms),
            markdown.generate_system_config_doc(device_id, **system_config_bundle),
            markdown.generate_policy_doc(device_id, policies),
            markdown.generate_routing_doc(device_id, static_routes, routing_table),
        ]
        content = "\n\n---\n\n".join(sections)
        return self._format_document(content)

    @service_operation("generate system configuration documentation")
    async def generate_system_config_doc(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        bundle = await self._fetch_system_config(device_id, vdom)
        content = markdown.generate_system_config_doc(device_id, **bundle)
        return self._format_document(content)

    @service_operation("generate VPN documentation")
    async def generate_vpn_doc(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)

        ipsec_tunnels = change_dispatch.unwrap_list(await adapter.list_ipsec_phase1(vdom=vdom))
        ipsec_phase2 = change_dispatch.unwrap_list(await adapter.list_ipsec_phase2(vdom=vdom))
        ipsec_status = change_dispatch.unwrap_list(await adapter.get_ipsec_tunnel_status(vdom=vdom))
        ssl_vpn_settings = change_dispatch.unwrap_single(await adapter.get_ssl_vpn_settings(vdom=vdom)) or {}
        ssl_vpn_sessions = change_dispatch.unwrap_list(await adapter.get_ssl_vpn_sessions(vdom=vdom))

        content = markdown.generate_vpn_doc(
            device_id, ipsec_tunnels, ipsec_phase2, ipsec_status, ssl_vpn_settings, len(ssl_vpn_sessions)
        )
        return self._format_document(content)
