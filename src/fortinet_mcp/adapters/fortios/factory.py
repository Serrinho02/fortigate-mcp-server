"""
Factory + registration helper for the FortiOS adapter.

Kept separate from `adapter.py` so `register_fortios_adapter` can be called
once during application wiring (Phase 1's `infra/di.py`) without every
caller needing to know `FortiOSAdapter`'s constructor signature.
"""
from __future__ import annotations

from src.fortigate_mcp.core.fortigate import FortiGateAPI

from ..registry import AdapterRegistry
from .adapter import FortiOSAdapter


def build_fortios_adapter(client: FortiGateAPI) -> FortiOSAdapter:
    return FortiOSAdapter(client)


def register_fortios_adapter(registry: AdapterRegistry) -> None:
    registry.register("fortios", build_fortios_adapter)
