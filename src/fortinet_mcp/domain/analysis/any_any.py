"""Detects overly permissive any-source/any-destination/any-service policies."""
from __future__ import annotations

from typing import Any

from ._util import is_wildcard, names


def find_any_any_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for policy in policies:
        src_wild = is_wildcard(names(policy.get("srcaddr")))
        dst_wild = is_wildcard(names(policy.get("dstaddr")))
        svc_wild = is_wildcard(names(policy.get("service")))
        if src_wild and dst_wild and svc_wild:
            findings.append(
                {
                    "policy_id": policy.get("policyid"),
                    "name": policy.get("name"),
                    "action": policy.get("action"),
                    "status": policy.get("status", "enable"),
                }
            )
    return findings
