"""
AnalysisService -- read-only security/hygiene analysis over a device's
live configuration (Phase 4). Every method here only issues GET-shaped
adapter calls; nothing routes through ChangeService because nothing here
mutates state.
"""
from __future__ import annotations

from typing import Any, List, Optional, Tuple

from mcp.types import TextContent as Content

from ..domain.analysis import any_any, best_practice, duplicate, overlap, scoring, shadowed, system_config, unused_objects
from . import change_dispatch
from .base import FortiGateServiceBase, service_operation


class AnalysisService(FortiGateServiceBase):
    """Each single-purpose method fetches only the data it needs (e.g.
    find_any_any only pulls policies) -- score_security/compliance_report
    are the only ones that genuinely need the full bundle."""

    async def _fetch_policies(self, device_id: str, vdom: Optional[str]) -> list:
        adapter = await self._get_adapter(device_id)
        return change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))

    async def _fetch_addresses(self, device_id: str, vdom: Optional[str]) -> list:
        adapter = await self._get_adapter(device_id)
        return change_dispatch.unwrap_list(await adapter.list_address_objects(vdom=vdom))

    async def _fetch_all(self, device_id: str, vdom: Optional[str]) -> Tuple[list, list, list, list]:
        adapter = await self._get_adapter(device_id)
        policies = change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))
        addresses = change_dispatch.unwrap_list(await adapter.list_address_objects(vdom=vdom))
        services = change_dispatch.unwrap_list(await adapter.list_service_objects(vdom=vdom))
        vips = change_dispatch.unwrap_list(await adapter.list_virtual_ips(vdom=vdom))
        return policies, addresses, services, vips

    async def _fetch_system_config(self, device_id: str, vdom: Optional[str]) -> dict[str, Any]:
        """Best-effort: a future non-FortiOS adapter might not implement
        every one of these, so each field degrades to empty/missing (and
        system_config.check_system_config treats that as "can't verify",
        not an error) rather than failing the whole analysis call."""
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

    @service_operation("find duplicate policies")
    async def find_duplicate_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies = await self._fetch_policies(device_id, vdom)
        findings = duplicate.find_duplicate_policies(policies)
        return self._format_analysis_result("Duplicate Policies", findings)

    @service_operation("find shadowed policies")
    async def find_shadowed_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies = await self._fetch_policies(device_id, vdom)
        findings = shadowed.find_shadowed_policies(policies)
        return self._format_analysis_result("Shadowed Policies", findings)

    @service_operation("find any-any policies")
    async def find_any_any(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies = await self._fetch_policies(device_id, vdom)
        findings = any_any.find_any_any_policies(policies)
        return self._format_analysis_result("Any-Any-Any Policies", findings)

    @service_operation("find unused objects")
    async def find_unused_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies, addresses, services, vips = await self._fetch_all(device_id, vdom)
        findings = {
            "unused_address_objects": unused_objects.find_unused(addresses, policies, ("srcaddr", "dstaddr")),
            "unused_service_objects": unused_objects.find_unused(services, policies, ("service",)),
            "unused_virtual_ips": unused_objects.find_unused(vips, policies, ("srcaddr", "dstaddr")),
        }
        return self._format_analysis_result("Unused Objects", findings)

    @service_operation("find overlapping subnets")
    async def find_overlapping_subnets(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        addresses = await self._fetch_addresses(device_id, vdom)
        findings = overlap.find_overlapping_subnets(addresses)
        return self._format_analysis_result("Overlapping Subnets", findings)

    @service_operation("check best practices")
    async def check_best_practices(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies = await self._fetch_policies(device_id, vdom)
        findings = best_practice.check_best_practices(policies)
        return self._format_analysis_result("Best Practice Findings", findings)

    @service_operation("check system configuration")
    async def check_system_config(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Best-practice heuristics over DNS/NTP/syslog/SNMP/admin/HA/
        hostname -- the system.*/vdom.* domain's counterpart to
        check_best_practices' policy checks."""
        bundle = await self._fetch_system_config(device_id, vdom)
        findings = system_config.check_system_config(**bundle)
        return self._format_analysis_result("System Configuration Findings", findings)

    def _score(
        self,
        policies: list,
        addresses: list,
        services: list,
        vips: list,
        system_config_issues: Optional[list] = None,
    ) -> dict[str, Any]:
        any_any_findings = any_any.find_any_any_policies(policies)
        shadowed_findings = shadowed.find_shadowed_policies(policies)
        duplicate_findings = duplicate.find_duplicate_policies(policies)
        unused_addr = unused_objects.find_unused(addresses, policies, ("srcaddr", "dstaddr"))
        unused_svc = unused_objects.find_unused(services, policies, ("service",))
        unused_vip = unused_objects.find_unused(vips, policies, ("srcaddr", "dstaddr"))
        best_practice_findings = best_practice.check_best_practices(policies)

        return scoring.score_security(
            any_any_count=len(any_any_findings),
            shadowed_count=len(shadowed_findings),
            duplicate_count=len(duplicate_findings),
            unused_count=len(unused_addr) + len(unused_svc) + len(unused_vip),
            best_practice_issues=best_practice_findings,
            system_config_issues=system_config_issues,
        )

    @service_operation("score security")
    async def score_security(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies, addresses, services, vips = await self._fetch_all(device_id, vdom)
        system_config_bundle = await self._fetch_system_config(device_id, vdom)
        system_config_issues = system_config.check_system_config(**system_config_bundle)
        result = self._score(policies, addresses, services, vips, system_config_issues)
        return self._format_analysis_result("Security Score", result)

    @service_operation("compliance report")
    async def compliance_report(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        policies, addresses, services, vips = await self._fetch_all(device_id, vdom)
        system_config_bundle = await self._fetch_system_config(device_id, vdom)
        system_config_issues = system_config.check_system_config(**system_config_bundle)

        report = {
            "security_score": self._score(policies, addresses, services, vips, system_config_issues),
            "any_any_policies": any_any.find_any_any_policies(policies),
            "shadowed_policies": shadowed.find_shadowed_policies(policies),
            "duplicate_policies": duplicate.find_duplicate_policies(policies),
            "overlapping_subnets": overlap.find_overlapping_subnets(addresses),
            "unused_address_objects": unused_objects.find_unused(addresses, policies, ("srcaddr", "dstaddr")),
            "unused_service_objects": unused_objects.find_unused(services, policies, ("service",)),
            "unused_virtual_ips": unused_objects.find_unused(vips, policies, ("srcaddr", "dstaddr")),
            "best_practice_findings": best_practice.check_best_practices(policies),
            "system_config_findings": system_config_issues,
        }
        return self._format_analysis_result("Compliance Report", report)
