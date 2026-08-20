"""
IntentService -- natural-language-shaped composite tools (Phase 7).
Claude does the actual language understanding; these methods take the
structured fields Claude has already extracted (zone names, a service
name, a policy id, ...) and do the FortiGate-specific legwork: resolving
fuzzy names against live configuration, and delegating any mutation to
the existing, already change-engine-gated services rather than executing
anything directly.
"""
from __future__ import annotations

from typing import Any, List, Optional

from mcp.types import TextContent as Content

from ..domain.analysis import any_any, best_practice, duplicate, scoring, shadowed, unused_objects
from ..domain.analysis.diagnosis import diagnose_policy, find_matching_policy
from . import change_dispatch
from .base import FortiGateServiceBase, service_operation
from .policy_service import PolicyService

_KNOWN_DEFAULT_SERVICES = {"HTTP", "HTTPS", "DNS", "SSH", "PING", "FTP", "SMTP", "TELNET", "NTP", "ALL"}


def _resolve_interface(zone: str, interfaces: list[dict[str, Any]], notes: list[str], label: str) -> str:
    iface_names = {i.get("name") for i in interfaces if i.get("name")}
    for candidate in iface_names:
        if candidate.lower() == zone.lower():
            return candidate
    notes.append(
        f"{label} zone '{zone}' did not match any existing interface name exactly -- "
        f"using '{zone}' as the interface name directly. Verify this is correct."
    )
    return zone


def _resolve_service(service: str, service_objects: list[dict[str, Any]], notes: list[str]) -> str:
    svc_names = {s.get("name") for s in service_objects if s.get("name")}
    for candidate in svc_names:
        if candidate.lower() == service.lower():
            return candidate
    if service.upper() in _KNOWN_DEFAULT_SERVICES:
        return service.upper()
    notes.append(
        f"Service '{service}' was not found among configured service objects and isn't one of "
        "FortiGate's common defaults; using it as-is. Create it first with create_service_object "
        "if it doesn't already exist on this device."
    )
    return service


def _resolve_address(zone: str, address_objects: list[dict[str, Any]]) -> Optional[str]:
    addr_names = {a.get("name") for a in address_objects if a.get("name")}
    for candidate in addr_names:
        if candidate.lower() == zone.lower():
            return candidate
    return None


class IntentService(FortiGateServiceBase):
    def __init__(self, fortigate_manager, policy_service: PolicyService, connection_manager=None):
        super().__init__(fortigate_manager, connection_manager=connection_manager)
        self._policy_service = policy_service

    @service_operation("create policy (intent)")
    async def create_policy(
        self,
        device_id: str,
        name: str,
        source_zone: str,
        dest_zone: str,
        service: str = "ALL",
        action: str = "accept",
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(name=name, source_zone=source_zone, dest_zone=dest_zone)

        adapter = await self._get_adapter(device_id)
        interfaces = change_dispatch.unwrap_list(await adapter.list_interfaces(vdom=vdom))
        service_objects = change_dispatch.unwrap_list(await adapter.list_service_objects(vdom=vdom))
        address_objects = change_dispatch.unwrap_list(await adapter.list_address_objects(vdom=vdom))

        notes: list[str] = []
        src_intf = _resolve_interface(source_zone, interfaces, notes, "Source")
        dst_intf = _resolve_interface(dest_zone, interfaces, notes, "Destination")
        resolved_service = _resolve_service(service, service_objects, notes)
        src_addr = _resolve_address(source_zone, address_objects) or "all"
        dst_addr = _resolve_address(dest_zone, address_objects) or "all"

        policy_data = {
            "name": name,
            "srcintf": [{"name": src_intf}],
            "dstintf": [{"name": dst_intf}],
            "srcaddr": [{"name": src_addr}],
            "dstaddr": [{"name": dst_addr}],
            "service": [{"name": resolved_service}],
            "action": action,
            "schedule": "always",
            "status": "enable",
        }

        preview = await self._policy_service.create_policy(device_id, policy_data, vdom)

        note_text = "\n".join(f"- {n}" for n in notes) if notes else "- Every field matched existing configuration directly."
        header = Content(type="text", text=f"Intent resolution notes:\n{note_text}\n")
        return [header, *preview]

    @service_operation("explain policy failure")
    async def explain_policy_failure(
        self, device_id: str, policy_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(policy_id=policy_id)

        adapter = await self._get_adapter(device_id)
        policies = change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))
        findings = diagnose_policy(policy_id, policies)
        return self._format_analysis_result(f"Policy {policy_id} Diagnosis", findings)

    @service_operation("summarize device")
    async def summarize_device(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)

        status = change_dispatch.unwrap_single(await adapter.get_status(vdom=vdom)) or {}
        interfaces = change_dispatch.unwrap_list(await adapter.list_interfaces(vdom=vdom))
        policies = change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))
        addresses = change_dispatch.unwrap_list(await adapter.list_address_objects(vdom=vdom))
        services = change_dispatch.unwrap_list(await adapter.list_service_objects(vdom=vdom))
        vips = change_dispatch.unwrap_list(await adapter.list_virtual_ips(vdom=vdom))

        up = sum(1 for i in interfaces if i.get("status", i.get("link")) == "up")
        down = len(interfaces) - up

        any_any_findings = any_any.find_any_any_policies(policies)
        score = scoring.score_security(
            any_any_count=len(any_any_findings),
            shadowed_count=len(shadowed.find_shadowed_policies(policies)),
            duplicate_count=len(duplicate.find_duplicate_policies(policies)),
            unused_count=(
                len(unused_objects.find_unused(addresses, policies, ("srcaddr", "dstaddr")))
                + len(unused_objects.find_unused(services, policies, ("service",)))
            ),
            best_practice_issues=best_practice.check_best_practices(policies),
        )

        lines = [
            f"# Device Summary -- {device_id}",
            "",
            f"- Hostname: {status.get('hostname', '-')}",
            f"- FortiOS version: {status.get('version', '-')}",
            f"- Interfaces: {len(interfaces)} total ({up} up, {down} down)",
            f"- Firewall policies: {len(policies)}",
            f"- Address objects: {len(addresses)}",
            f"- Service objects: {len(services)}",
            f"- Virtual IPs: {len(vips)}",
            f"- Security score: {score['score']}/100 (grade {score['grade']})",
        ]
        if any_any_findings:
            plural = "y" if len(any_any_findings) == 1 else "ies"
            lines.append(f"- WARNING: {len(any_any_findings)} any-any-any polic{plural} present.")

        return self._format_document("\n".join(lines))

    @service_operation("find path")
    async def find_path(
        self,
        device_id: str,
        source: str,
        destination: str,
        service: Optional[str] = None,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(source=source, destination=destination)

        adapter = await self._get_adapter(device_id)
        policies = change_dispatch.unwrap_list(await adapter.list_policies(vdom=vdom))
        match = find_matching_policy(policies, source, destination, service)

        if match is None:
            return self._format_analysis_result(
                "Path Analysis",
                {
                    "source": source,
                    "destination": destination,
                    "service": service,
                    "result": "no_match",
                    "explanation": "No enabled policy matches this traffic; FortiGate's implicit deny-all applies.",
                },
            )

        return self._format_analysis_result(
            "Path Analysis",
            {
                "source": source,
                "destination": destination,
                "service": service,
                "result": "matched",
                "policy_id": match.get("policyid"),
                "policy_name": match.get("name"),
                "action": match.get("action"),
            },
        )
