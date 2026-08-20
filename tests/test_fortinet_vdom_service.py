"""
Tests for VdomService: VDOM create/delete and inter-VDOM link CRUD, all
mutations through the real change engine (preview -> apply), exactly like
PolicyService/VpnService/SystemService.
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.vdom_service import VdomService


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
    return VdomService(fortigate_manager, change_service)


@pytest.fixture
def registered(fortigate_manager, mock_fortigate_api):
    fortigate_manager.devices["test_device"] = mock_fortigate_api
    return mock_fortigate_api


def _change_id_from(result) -> str:
    for content in result:
        for line in content.text.splitlines():
            if "change_id:" in line:
                return line.split("change_id:", 1)[1].strip()
    raise AssertionError("no change_id found in result")


class TestCreateDeleteVdom:
    @pytest.mark.asyncio
    async def test_create_vdom_previews_without_executing(self, service, registered):
        result = await service.create_vdom("test_device", {"name": "Alfa"})
        registered.create_vdom.assert_not_awaited()
        assert "change_id" in result[0].text

    @pytest.mark.asyncio
    async def test_create_vdom_preview_then_apply_executes(self, service, change_service, registered):
        vdom_data = {"name": "Alfa"}
        preview_result = await service.create_vdom("test_device", vdom_data)
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_vdom.assert_awaited_once_with(vdom_data)

    @pytest.mark.asyncio
    async def test_create_vdom_missing_data_returns_error(self, service, registered):
        result = await service.create_vdom("test_device", None)
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_delete_vdom_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_vdom("test_device", "Alfa")
        registered.delete_vdom.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.delete_vdom.assert_awaited_once_with("Alfa")


class TestVdomLinks:
    @pytest.mark.asyncio
    async def test_list_vdom_links_delegates(self, service, registered):
        result = await service.list_vdom_links("test_device")
        registered.get_vdom_links.assert_awaited_once_with()
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_vdom_link_preview_then_apply(self, service, change_service, registered):
        link_data = {"name": "link1"}
        preview_result = await service.create_vdom_link("test_device", link_data)
        registered.create_vdom_link.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_vdom_link.assert_awaited_once_with(link_data)

    @pytest.mark.asyncio
    async def test_delete_vdom_link_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_vdom_link("test_device", "link1")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_vdom_link.assert_awaited_once_with("link1")


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_create_vdom_blocked_in_read_only_mode(self, fortigate_manager, session_factory, registered):
        read_only_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.READ_ONLY))
        service = VdomService(fortigate_manager, read_only_service)

        result = await service.create_vdom("test_device", {"name": "Alfa"})

        assert "read_only" in result[0].text.lower()
        registered.create_vdom.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_vdom_blocked_in_safe_mode(self, fortigate_manager, session_factory, registered):
        safe_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.SAFE))
        service = VdomService(fortigate_manager, safe_service)

        result = await service.delete_vdom("test_device", "Alfa")

        assert "safe" in result[0].text.lower()
        registered.delete_vdom.assert_not_awaited()


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.list_vdom_links("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
