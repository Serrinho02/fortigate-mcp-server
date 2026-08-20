"""
Tests for the change.* MCP tools (mcp/tools/change_tools.py), using a real
ChangeService (FULL mode, temp-file SQLite) plus the mocked FortiGateAPI
fixture -- exercises the full preview -> change_apply(change_id) path
through the actual tool functions FastMCP would call.
"""
import pytest
import pytest_asyncio
from mcp.server.fastmcp import FastMCP

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.mcp.tools.change_tools import register_change_tools
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode, OperationType


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'inventory.db').as_posix()}"
    engine = create_engine(db_url)
    await init_models(engine)
    factory = create_session_factory(engine)
    yield factory
    await engine.dispose()


@pytest.fixture
def registered(fortigate_manager, mock_fortigate_api):
    fortigate_manager.devices["test_device"] = mock_fortigate_api
    return mock_fortigate_api


@pytest.fixture
def change_service(fortigate_manager, session_factory):
    return ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.FULL))


def _tools_from(mcp: FastMCP) -> dict:
    """Direct access to each tool's underlying function, bypassing the
    JSON-content wrapping `mcp.call_tool` does -- these are unit tests of
    the tool bodies, not of MCP's own serialization."""
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}


@pytest.fixture
def tools(change_service):
    mcp = FastMCP("test")
    register_change_tools(mcp, change_service)
    return _tools_from(mcp)


class TestChangeApplyTool:
    @pytest.mark.asyncio
    async def test_apply_unknown_change_id_returns_error_dict(self, tools, registered):
        result = await tools["change_apply"](change_id="chg_bogus")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_apply_executes_a_previewed_create(
        self, tools, change_service, registered, sample_policy_data
    ):
        preview = await change_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        result = await tools["change_apply"](change_id=preview.change_id)

        assert result["change_id"] == preview.change_id
        assert result["operation"] == "create"
        registered.create_firewall_policy.assert_awaited_once_with(sample_policy_data, vdom="root")


class TestChangeRollbackTool:
    @pytest.mark.asyncio
    async def test_rollback_unknown_change_id_returns_error_dict(self, tools, registered):
        result = await tools["change_rollback"](change_id="chg_bogus")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_rollback_update_restores_previous_values(self, tools, change_service, registered):
        preview = await change_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.UPDATE, resource_id="35", proposed_data={"action": "deny"},
        )
        await change_service.apply(preview.change_id)

        result = await tools["change_rollback"](change_id=preview.change_id)

        assert result["operation"] == "update"
        registered.update_firewall_policy.assert_any_call("35", preview.before, vdom="root")

    @pytest.mark.asyncio
    async def test_rollback_of_pending_change_returns_error_dict(
        self, tools, change_service, registered, sample_policy_data
    ):
        preview = await change_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        result = await tools["change_rollback"](change_id=preview.change_id)

        assert "error" in result


class TestChangeListPendingAndHistory:
    @pytest.mark.asyncio
    async def test_list_pending_reflects_proposed_changes(
        self, tools, change_service, registered, sample_policy_data
    ):
        preview = await change_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        pending = await tools["change_list_pending"]()

        assert [c["change_id"] for c in pending] == [preview.change_id]

    @pytest.mark.asyncio
    async def test_history_reflects_all_statuses(
        self, tools, change_service, registered, sample_policy_data
    ):
        preview = await change_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        await change_service.apply(preview.change_id)

        history = await tools["change_history"](limit=10)

        assert history[0]["change_id"] == preview.change_id
        assert history[0]["status"] == "applied"


class TestModeEnforcementThroughTools:
    @pytest.mark.asyncio
    async def test_apply_rejected_when_mode_becomes_read_only(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        full_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.FULL))
        preview = await full_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        read_only_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.READ_ONLY))
        mcp2 = FastMCP("test2")
        register_change_tools(mcp2, read_only_service)
        apply_tool_read_only = _tools_from(mcp2)["change_apply"]

        result = await apply_tool_read_only(change_id=preview.change_id)

        assert "error" in result
        assert "read_only" in result["error"].lower()
