"""
Pure comparison of two resource lists (e.g. device A's firewall policies
vs device B's), keyed by whatever field is stable/unique for that resource
type. No I/O -- fleet_service.py fetches the live lists and hands them here.
"""
from __future__ import annotations

from typing import Any

from .diff import compute_diff


def _key_for(resource_type: str, item: dict[str, Any]) -> Any:
    if resource_type == "firewall_policy":
        return item.get("policyid")
    if resource_type == "static_route":
        return item.get("seq-num", item.get("dst"))
    return item.get("name")


def compare_resource_lists(
    resource_type: str, items_a: list[dict[str, Any]], items_b: list[dict[str, Any]]
) -> dict[str, Any]:
    by_key_a = {_key_for(resource_type, item): item for item in items_a}
    by_key_b = {_key_for(resource_type, item): item for item in items_b}
    keys_a, keys_b = set(by_key_a), set(by_key_b)

    only_in_a = sorted(keys_a - keys_b, key=str)
    only_in_b = sorted(keys_b - keys_a, key=str)

    identical, different = [], []
    for key in sorted(keys_a & keys_b, key=str):
        item_a, item_b = by_key_a[key], by_key_b[key]
        if item_a == item_b:
            identical.append(key)
        else:
            diff = compute_diff("update", item_a, item_b)
            different.append({"key": key, "changed_fields": diff["changed_fields"]})

    return {
        "resource_type": resource_type,
        "only_in_a": only_in_a,
        "only_in_b": only_in_b,
        "identical": identical,
        "different": different,
    }
