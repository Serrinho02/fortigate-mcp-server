"""
A small set of Fortinet-style best-practice heuristics over firewall
policies. Deliberately modest in scope for this first cut of the analysis
engine -- easy to extend with more checks later without touching callers.
"""
from __future__ import annotations

from typing import Any


def check_best_practices(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for policy in policies:
        policy_id = policy.get("policyid")

        if policy.get("action") == "accept" and policy.get("logtraffic", "disable") == "disable":
            findings.append(
                {
                    "policy_id": policy_id,
                    "severity": "medium",
                    "issue": "Accept policy has traffic logging disabled, reducing audit visibility.",
                }
            )

        if not policy.get("comments"):
            findings.append(
                {
                    "policy_id": policy_id,
                    "severity": "low",
                    "issue": "Policy has no comment/description.",
                }
            )

        if policy.get("status") == "disable":
            findings.append(
                {
                    "policy_id": policy_id,
                    "severity": "low",
                    "issue": "Policy is disabled but still present in the ruleset -- remove if permanently unused.",
                }
            )

    return findings
