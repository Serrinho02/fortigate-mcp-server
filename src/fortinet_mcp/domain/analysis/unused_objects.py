"""
Unused object detection: address objects, service objects, and virtual
IPs (VIPs can be used as a policy's dstaddr for DNAT) that no policy
references anywhere in the given fields.
"""
from __future__ import annotations

from typing import Any, Sequence

from ._util import names


def find_unused(
    objects: list[dict[str, Any]], policies: list[dict[str, Any]], reference_fields: Sequence[str]
) -> list[str]:
    referenced: set[str] = set()
    for policy in policies:
        for field in reference_fields:
            referenced |= names(policy.get(field))

    return [obj["name"] for obj in objects if obj.get("name") and obj["name"] not in referenced]
