"""
Tests for PolicyService (Phase 2 migration of tools/firewall.py, Phase 3
change-engine wiring). create/update/delete now preview instead of
executing immediately -- a real ChangeService (FULL mode, temp-file
SQLite) verifies the full preview -> apply chain actually reaches the
adapter, not just that a preview object gets returned.
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.policy_service import PolicyService


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'inventory.db').as_posix()}"
    engine = create_engine(db_url)
    await init_models(engine)
    factory = create_session_factory(engine)
    yield factory
    await engine.dispose()


@pytest.fixture
def change_service(fortigate_manager, session_factory):
    return ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.FULL))


@pytest.fixture
def service(fortigate_manager, change_service):
    return PolicyService(fortigate_manager, change_service)


@pytest.fixture
def registered(fortigate_manager, mock_fortigate_api):
    fortigate_manager.devices["test_device"] = mock_fortigate_api
    return mock_fortigate_api


def _change_id_from(result) -> str:
    text = result[0].text
    for line in text.splitlines():
        if "change_id:" in line:
            return line.split("change_id:", 1)[1].strip()
    raise AssertionError(f"no change_id found in: {text}")


class TestListPolicies:
    @pytest.mark.asyncio
    async def test_list_policies_delegates_with_vdom(self, service, registered):
        result = await service.list_policies("test_device", vdom="root")
        registered.get_firewall_policies.assert_awaited_once_with(vdom="root")
        assert result is not None


class TestCreatePolicyPreview:
    @pytest.mark.asyncio
    async def test_create_policy_returns_preview_without_executing(self, service, registered, sample_policy_data):
        result = await service.create_policy("test_device", sample_policy_data)

        registered.create_firewall_policy.assert_not_awaited()
        text = result[0].text
        assert "change_id" in text
        assert "change.apply" in text

    @pytest.mark.asyncio
    async def test_create_policy_missing_data_returns_error(self, service, registered):
        result = await service.create_policy("test_device", None)
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_create_policy_preview_then_apply_executes(self, service, change_service, registered, sample_policy_data):
        preview_result = await service.create_policy("test_device", sample_policy_data)
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_firewall_policy.assert_awaited_once_with(sample_policy_data, vdom=None)


class TestUpdatePolicyPreview:
    @pytest.mark.asyncio
    async def test_update_policy_preview_then_apply_executes(self, service, change_service, registered, sample_policy_data):
        preview_result = await service.update_policy("test_device", "35", sample_policy_data)
        registered.update_firewall_policy.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.update_firewall_policy.assert_awaited_once_with("35", sample_policy_data, vdom=None)


class TestDeletePolicyPreview:
    @pytest.mark.asyncio
    async def test_delete_policy_preview_then_apply_executes(self, service, change_service, registered):
        preview_result = await service.delete_policy("test_device", "35")
        registered.delete_firewall_policy.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.delete_firewall_policy.assert_awaited_once_with("35", vdom=None)


class TestGetPolicyDetail:
    """Read-only -- unaffected by the change engine, still executes immediately."""

    @pytest.mark.asyncio
    async def test_get_policy_detail_resolves_address_and_service_objects(self, service, registered):
        result = await service.get_policy_detail("test_device", "35")

        registered.get_firewall_policy_detail.assert_awaited_once_with("35", vdom=None)
        registered.get_address_objects.assert_awaited_once_with(vdom=None)
        registered.get_service_objects.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_policy_detail_survives_address_object_lookup_failure(self, service, registered):
        registered.get_address_objects.side_effect = Exception("boom")
        result = await service.get_policy_detail("test_device", "35")
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_policy_detail_survives_service_object_lookup_failure(self, service, registered):
        registered.get_service_objects.side_effect = Exception("boom")
        result = await service.get_policy_detail("test_device", "35")
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_policy_detail_missing_policy_id_returns_error(self, service, registered):
        result = await service.get_policy_detail("test_device", "")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_create_policy_blocked_in_read_only_mode(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        read_only_change_service = ChangeService(
            fortigate_manager, session_factory, ModePolicy(OperatingMode.READ_ONLY)
        )
        service = PolicyService(fortigate_manager, read_only_change_service)

        result = await service.create_policy("test_device", sample_policy_data)

        assert "read_only" in result[0].text.lower()
        registered.create_firewall_policy.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_policy_blocked_in_safe_mode(self, fortigate_manager, session_factory, registered):
        safe_change_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.SAFE))
        service = PolicyService(fortigate_manager, safe_change_service)

        result = await service.delete_policy("test_device", "35")

        assert "safe" in result[0].text.lower()
        registered.delete_firewall_policy.assert_not_awaited()


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.list_policies("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
