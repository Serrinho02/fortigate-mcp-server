"""
DiffEngine -- computes a human-and-machine-readable diff for a proposed
change against the resource's current state. FortiOS resources are plain
JSON dicts, so this is a straightforward key-level comparison; nothing
here is FortiOS-specific, so it applies unchanged to future adapters.
"""
from __future__ import annotations

from typing import Any, Optional


def compute_diff(
    operation: str, before: Optional[dict[str, Any]], after: Optional[dict[str, Any]]
) -> dict[str, Any]:
    """
    Args:
        operation: "create", "update", or "delete".
        before: current resource state, or None (a CREATE has nothing to diff against).
        after: proposed resource state, or None (a DELETE has no new state).
    """
    if operation == "create":
        return {"operation": "create", "added": after or {}}
    if operation == "delete":
        return {"operation": "delete", "removed": before or {}}
    if operation == "update":
        before = before or {}
        after = after or {}
        changed_fields: dict[str, Any] = {}
        for key in sorted(set(before) | set(after)):
            before_value, after_value = before.get(key), after.get(key)
            if before_value != after_value:
                changed_fields[key] = {"before": before_value, "after": after_value}
        return {"operation": "update", "changed_fields": changed_fields}
    raise ValueError(f"Unknown operation: {operation!r}")
