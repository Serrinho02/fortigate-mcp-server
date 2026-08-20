"""Shared helpers for the analysis modules -- not part of the public API."""
from __future__ import annotations

from typing import Any, Optional

_WILDCARDS = {"all", "any"}


def names(field: Optional[list]) -> frozenset[str]:
    """FortiOS list-of-object fields (srcintf, srcaddr, service, ...) are
    `[{"name": "x"}, ...]`; reduce to the set of names."""
    if not field:
        return frozenset()
    return frozenset(item.get("name", "") for item in field if isinstance(item, dict))


def is_wildcard(name_set: frozenset[str]) -> bool:
    return any(n.lower() in _WILDCARDS for n in name_set)


def field_covers(earlier: frozenset[str], later: frozenset[str]) -> bool:
    """True if `earlier` (a policy evaluated first) matches every value
    `later` (a policy evaluated after it) would match, for one field."""
    if is_wildcard(earlier):
        return True
    if is_wildcard(later):
        return False
    return later.issubset(earlier)
