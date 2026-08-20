"""
Shadowed policy detection: FortiGate evaluates policies top-down and stops
at the first match, so a later policy whose match criteria is entirely
covered by an earlier, enabled policy can never actually fire.
"""
from __future__ import annotations

from typing import Any

from ._util import field_covers, names

_MATCH_FIELDS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")


def _shadows(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    return all(
        field_covers(names(earlier.get(field)), names(later.get(field))) for field in _MATCH_FIELDS
    )


def find_shadowed_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order matters: `policies` must be in FortiGate's evaluation order
    (the order `list_policies` returns them in)."""
    enabled = [p for p in policies if p.get("status", "enable") != "disable"]

    findings = []
    for i, earlier in enumerate(enabled):
        for later in enabled[i + 1 :]:
            if _shadows(earlier, later):
                findings.append(
                    {
                        "shadowed_policy_id": later.get("policyid"),
                        "shadowed_by_policy_id": earlier.get("policyid"),
                        "reason": (
                            f"Policy {earlier.get('policyid')} is evaluated first and matches "
                            f"all traffic policy {later.get('policyid')} would match."
                        ),
                    }
                )
    return findings
