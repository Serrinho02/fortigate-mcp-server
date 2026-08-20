"""
Tests for ChangeService: the preview -> apply -> rollback lifecycle,
mode enforcement, drift detection, and expiry. Uses the same
mock_fortigate_api/fortigate_manager fixtures as the Service-layer tests,
plus a temp-file SQLite session_factory (ChangeRecord persistence must
survive across separate preview/apply/rollback calls, unlike ":memory:"
which is per-connection).
"""
from datetime import timedelta

import pytest
import pytest_asyncio

from src.fortinet_mcp.errors import (
    ChangeAlreadyResolvedError,
    ChangeDriftError,
    ChangeExpiredError,
    ChangeNotFoundError,
    ModeViolationError,
    RollbackNotPossibleError,
)
from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.infra.models_orm import utcnow_naive
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


def change_service(fortigate_manager, session_factory, mode=OperatingMode.FULL):
    return ChangeService(fortigate_manager, session_factory, ModePolicy(mode))


class TestPreviewModeEnforcement:
    @pytest.mark.asyncio
    async def test_read_only_blocks_create(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory, OperatingMode.READ_ONLY)
        with pytest.raises(ModeViolationError):
            await service.preview(
                device_id="test_device", vdom="root", resource_type="firewall_policy",
                operation=OperationType.CREATE, resource_id=None, proposed_data={"name": "x"},
            )

    @pytest.mark.asyncio
    async def test_safe_blocks_delete_but_allows_create(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory, OperatingMode.SAFE)
        with pytest.raises(ModeViolationError):
            await service.preview(
                device_id="test_device", vdom="root", resource_type="firewall_policy",
                operation=OperationType.DELETE, resource_id="35", proposed_data=None,
            )
        # create is still fine in SAFE mode
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data={"name": "x"},
        )
        assert preview.change_id.startswith("chg_")


class TestPreviewDiff:
    @pytest.mark.asyncio
    async def test_create_diff_has_no_before_state(self, fortigate_manager, session_factory, registered, sample_policy_data):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        assert preview.before is None
        assert preview.diff == {"operation": "create", "added": sample_policy_data}

    @pytest.mark.asyncio
    async def test_delete_diff_fetches_current_state(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.DELETE, resource_id="35", proposed_data=None,
        )
        registered.get_firewall_policy_detail.assert_awaited_once_with("35", vdom="root")
        assert preview.before["policyid"] == 35
        assert preview.diff["operation"] == "delete"


class TestApplyLifecycle:
    @pytest.mark.asyncio
    async def test_apply_create_executes_and_marks_applied(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        result = await service.apply(preview.change_id)

        registered.create_firewall_policy.assert_awaited_once_with(sample_policy_data, vdom="root")
        assert result.change_id == preview.change_id

    @pytest.mark.asyncio
    async def test_apply_unknown_change_id_raises(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory)
        with pytest.raises(ChangeNotFoundError):
            await service.apply("chg_doesnotexist")

    @pytest.mark.asyncio
    async def test_apply_twice_raises_already_resolved(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        await service.apply(preview.change_id)

        with pytest.raises(ChangeAlreadyResolvedError):
            await service.apply(preview.change_id)

    @pytest.mark.asyncio
    async def test_apply_after_expiry_raises_and_marks_expired(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        from sqlalchemy import select
        from src.fortinet_mcp.infra.models_orm import ChangeRecord

        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        async with session_factory() as session:
            record = (
                await session.execute(select(ChangeRecord).where(ChangeRecord.change_id == preview.change_id))
            ).scalar_one()
            record.expires_at = utcnow_naive() - timedelta(seconds=1)
            await session.commit()

        with pytest.raises(ChangeExpiredError):
            await service.apply(preview.change_id)

        pending = await service.list_pending()
        assert pending == []

    @pytest.mark.asyncio
    async def test_apply_detects_drift_since_preview(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.UPDATE, resource_id="35", proposed_data={"action": "deny"},
        )

        # simulate the live policy changing after the preview was computed
        registered.get_firewall_policy_detail.return_value = {
            "results": {"policyid": 35, "name": "changed-elsewhere", "action": "accept"}
        }

        with pytest.raises(ChangeDriftError):
            await service.apply(preview.change_id)

    @pytest.mark.asyncio
    async def test_apply_blocked_if_mode_changed_to_read_only_after_preview(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        preview_service = change_service(fortigate_manager, session_factory, OperatingMode.FULL)
        preview = await preview_service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )

        readonly_service = change_service(fortigate_manager, session_factory, OperatingMode.READ_ONLY)
        with pytest.raises(ModeViolationError):
            await readonly_service.apply(preview.change_id)


class TestRollback:
    @pytest.mark.asyncio
    async def test_rollback_update_restores_previous_values(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.UPDATE, resource_id="35", proposed_data={"action": "deny"},
        )
        await service.apply(preview.change_id)

        result = await service.rollback(preview.change_id)

        # rolled back to the "before" state captured at preview time
        registered.update_firewall_policy.assert_any_call("35", preview.before, vdom="root")
        assert result.operation == "update"

    @pytest.mark.asyncio
    async def test_rollback_create_without_mkey_is_not_possible(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        await service.apply(preview.change_id)  # mock create response has no "mkey"

        with pytest.raises(RollbackNotPossibleError):
            await service.rollback(preview.change_id)

    @pytest.mark.asyncio
    async def test_rollback_create_with_mkey_deletes_created_resource(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        registered.create_firewall_policy.return_value = {"status": "success", "mkey": "99"}
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        await service.apply(preview.change_id)

        result = await service.rollback(preview.change_id)

        registered.delete_firewall_policy.assert_awaited_once_with("99", vdom="root")
        assert result.operation == "create"

    @pytest.mark.asyncio
    async def test_rollback_delete_recreates_from_before_state(self, fortigate_manager, session_factory, registered):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.DELETE, resource_id="35", proposed_data=None,
        )
        await service.apply(preview.change_id)

        result = await service.rollback(preview.change_id)

        registered.create_firewall_policy.assert_awaited_once_with(preview.before, vdom="root")
        assert "best-effort" in result.note.lower()

    @pytest.mark.asyncio
    async def test_rollback_of_non_applied_change_raises(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        service = change_service(fortigate_manager, session_factory)
        preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        with pytest.raises(ChangeAlreadyResolvedError):
            await service.rollback(preview.change_id)  # still "proposed", never applied


class TestListPendingAndHistory:
    @pytest.mark.asyncio
    async def test_list_pending_excludes_applied_changes(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        service = change_service(fortigate_manager, session_factory)
        applied_preview = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        await service.apply(applied_preview.change_id)

        still_pending = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data={"name": "other"},
        )

        pending = await service.list_pending()

        assert [r.change_id for r in pending] == [still_pending.change_id]

    @pytest.mark.asyncio
    async def test_history_returns_most_recent_first(
        self, fortigate_manager, session_factory, registered, sample_policy_data
    ):
        service = change_service(fortigate_manager, session_factory)
        first = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data=sample_policy_data,
        )
        second = await service.preview(
            device_id="test_device", vdom="root", resource_type="firewall_policy",
            operation=OperationType.CREATE, resource_id=None, proposed_data={"name": "other"},
        )

        history = await service.history(limit=10)

        assert history[0].change_id == second.change_id
        assert history[1].change_id == first.change_id
