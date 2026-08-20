"""
ModePolicy -- the single READ_ONLY/SAFE/FULL gate every mutating operation
passes through via ChangeService (see architecture plan §9). Global for
v1: one mode for the whole server process, read once at startup from
`FORTINET_MCP_MODE`. The data model doesn't block a future per-customer/
per-site override -- this class is where that override would plug in
without changing any caller.
"""
from __future__ import annotations

import os
from enum import Enum

from ..errors import ModeViolationError


class OperatingMode(str, Enum):
    READ_ONLY = "read_only"
    SAFE = "safe"
    FULL = "full"


class OperationType(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class ModePolicy:
    """Decisive simplification (confirmed in the architecture plan): every
    mode always requires preview+apply for every mutation. FULL never gets
    a single-shot fast path -- the only difference between modes is *which*
    operations may even be previewed at all."""

    def __init__(self, mode: OperatingMode):
        self.mode = mode

    def check(self, operation: OperationType) -> None:
        """Raise ModeViolationError if `operation` may not even be previewed
        in the current mode. Does not grant execution -- change.apply is
        always still required afterwards, in every mode."""
        if self.mode is OperatingMode.READ_ONLY:
            raise ModeViolationError(
                "Server is in READ_ONLY mode: no changes are permitted."
            )
        if self.mode is OperatingMode.SAFE and operation is OperationType.DELETE:
            raise ModeViolationError(
                "Server is in SAFE mode: delete operations are not permitted."
            )

    @classmethod
    def from_env(
        cls, env_var: str = "FORTINET_MCP_MODE", default: OperatingMode = OperatingMode.FULL
    ) -> "ModePolicy":
        raw = os.getenv(env_var)
        if not raw:
            return cls(default)
        try:
            return cls(OperatingMode(raw.strip().lower()))
        except ValueError:
            valid = ", ".join(m.value for m in OperatingMode)
            raise ValueError(f"Invalid {env_var} value {raw!r}; expected one of: {valid}") from None
