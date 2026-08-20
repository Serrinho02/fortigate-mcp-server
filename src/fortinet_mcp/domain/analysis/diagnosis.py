"""
Policy-level diagnostics reused by the Phase 7 intent.* composites:
`diagnose_policy` explains why a specific policy might not be matching
traffic as expected (intent.explain_policy_failure); `find_matching_policy`
simulates FortiGate's first-match-wins evaluation for a given traffic
tuple (intent.find_path).
"""
from __future__ import annotations

from typing import Any, Optional

from ._util import field_covers, is_wildcard, names
from .shadowed import find_shadowed_policies

_MATCH_FIELDS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")


def _find_by_id(policy_id: Any, policies: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    target = str(policy_id)
    return next((p for p in policies if str(p.get("policyid")) == target), None)


def _earlier_deny_covering(policy_id: Any, policies: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """The first enabled `deny` policy, evaluated before `policy_id`, whose
    match criteria covers everything the target policy would match --
    traffic never reaches the target because it's denied earlier."""
    target = _find_by_id(policy_id, policies)
    if target is None:
        return None
    for policy in policies:
        if str(policy.get("policyid")) == str(policy_id):
            break
        if policy.get("status") == "disable" or policy.get("action") != "deny":
            continue
        if all(field_covers(names(policy.get(f)), names(target.get(f))) for f in _MATCH_FIELDS):
            return policy
    return None


def diagnose_policy(policy_id: Any, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Heuristic explanations for why `policy_id` might not be behaving as
    expected. Not a live traffic/session trace (no adapter exposes that) --
    a configuration-level review only."""
    target = _find_by_id(policy_id, policies)
    if target is None:
        return [{"issue": "not_found", "detail": f"No policy with id {policy_id} exists on this device."}]

    findings = []

    if target.get("status") == "disable":
        findings.append(
            {"issue": "disabled", "detail": "The policy is disabled (status=disable) and will never match traffic."}
        )

    shadow = next(
        (f for f in find_shadowed_policies(policies) if str(f["shadowed_policy_id"]) == str(policy_id)),
        None,
    )
    if shadow:
        findings.append({"issue": "shadowed", "detail": shadow["reason"]})

    schedule = target.get("schedule", "always")
    if schedule and schedule != "always":
        findings.append(
            {
                "issue": "schedule_restricted",
                "detail": f"The policy only applies during schedule '{schedule}', not at all times.",
            }
        )

    denying_policy = _earlier_deny_covering(policy_id, policies)
    if denying_policy:
        findings.append(
            {
                "issue": "denied_earlier",
                "detail": (
                    f"Policy {denying_policy.get('policyid')} is an earlier, enabled deny rule that "
                    f"matches all the same traffic and is evaluated first."
                ),
            }
        )

    if not findings:
        findings.append(
            {
                "issue": "no_obvious_issue",
                "detail": (
                    "No obvious configuration issue found. If traffic still isn't matching, check "
                    "routing, NAT, and interface/zone assignment, or session logs on the device directly."
                ),
            }
        )
    return findings


def find_matching_policy(
    policies: list[dict[str, Any]],
    source: str,
    destination: str,
    service: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Simulates FortiGate's first-match-wins evaluation for one traffic
    tuple. `source`/`destination` must be address object names (or "any");
    raw IPs aren't resolved against object subnets in this v1 scope."""
    for policy in policies:
        if policy.get("status") == "disable":
            continue

        src_names, dst_names = names(policy.get("srcaddr")), names(policy.get("dstaddr"))
        if not (is_wildcard(src_names) or source in src_names):
            continue
        if not (is_wildcard(dst_names) or destination in dst_names):
            continue

        if service is not None:
            svc_names = names(policy.get("service"))
            if not (is_wildcard(svc_names) or service in svc_names):
                continue

        return policy
    return None
