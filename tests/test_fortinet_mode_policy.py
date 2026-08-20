"""Tests for ModePolicy (READ_ONLY/SAFE/FULL enforcement)."""
import pytest

from src.fortinet_mcp.errors import ModeViolationError
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode, OperationType


class TestReadOnlyMode:
    @pytest.mark.parametrize("operation", [OperationType.CREATE, OperationType.UPDATE, OperationType.DELETE])
    def test_blocks_every_operation(self, operation):
        policy = ModePolicy(OperatingMode.READ_ONLY)
        with pytest.raises(ModeViolationError, match="READ_ONLY"):
            policy.check(operation)


class TestSafeMode:
    def test_blocks_delete(self):
        policy = ModePolicy(OperatingMode.SAFE)
        with pytest.raises(ModeViolationError, match="SAFE"):
            policy.check(OperationType.DELETE)

    @pytest.mark.parametrize("operation", [OperationType.CREATE, OperationType.UPDATE])
    def test_allows_create_and_update(self, operation):
        policy = ModePolicy(OperatingMode.SAFE)
        policy.check(operation)  # must not raise


class TestFullMode:
    @pytest.mark.parametrize("operation", [OperationType.CREATE, OperationType.UPDATE, OperationType.DELETE])
    def test_allows_every_operation(self, operation):
        policy = ModePolicy(OperatingMode.FULL)
        policy.check(operation)  # must not raise


class TestFromEnv:
    def test_defaults_to_full_when_unset(self, monkeypatch):
        monkeypatch.delenv("FORTINET_MCP_MODE", raising=False)
        policy = ModePolicy.from_env()
        assert policy.mode is OperatingMode.FULL

    def test_reads_valid_value_case_insensitively(self, monkeypatch):
        monkeypatch.setenv("FORTINET_MCP_MODE", "Read_Only")
        policy = ModePolicy.from_env()
        assert policy.mode is OperatingMode.READ_ONLY

    def test_invalid_value_raises_with_clear_message(self, monkeypatch):
        monkeypatch.setenv("FORTINET_MCP_MODE", "yolo")
        with pytest.raises(ValueError, match="Invalid FORTINET_MCP_MODE"):
            ModePolicy.from_env()
