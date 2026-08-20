"""Duplicate policy detection: identical match criteria AND identical
action, so removing either one has zero effect on traffic handling.
(Same criteria with *different* actions is a shadowing problem, not a
pure duplicate -- see shadowed.py.)"""
from __future__ import annotations

from typing import Any

from ._util import names

_MATCH_FIELDS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")


def find_duplicate_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for policy in policies:
        key = tuple(names(policy.get(field)) for field in _MATCH_FIELDS) + (policy.get("action"),)
        groups.setdefault(key, []).append(policy)

    duplicates = []
    for key, group in groups.items():
        if len(group) > 1:
            match_criteria = {field: sorted(value) for field, value in zip(_MATCH_FIELDS, key)}
            match_criteria["action"] = key[-1]
            duplicates.append(
                {
                    "policy_ids": [p.get("policyid") for p in group],
                    "match_criteria": match_criteria,
                }
            )
    return duplicates
