"""Shared helpers for the docsgen modules -- not part of the public API."""
from __future__ import annotations

import re
from typing import Any, Optional


def field_names(field: Optional[list]) -> list[str]:
    """FortiOS list-of-object fields (srcintf, srcaddr, service, ...) are
    `[{"name": "x"}, ...]`; reduce to a stable, sorted list of names."""
    if not field:
        return []
    return sorted(item.get("name", "") for item in field if isinstance(item, dict))


def join_names(field: Optional[list], sep: str = ", ") -> str:
    return sep.join(field_names(field))


def safe_id(name: str) -> str:
    """Sanitize a FortiOS object name into a safe diagram node identifier
    (alphanumeric + underscore only)."""
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return sanitized if sanitized and sanitized[0].isalpha() else f"n_{sanitized}"


def escape_markdown_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")
