"""
Tests for VipService (Phase 2 migration of tools/virtual_ip.py, Phase 3
change-engine wiring).
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.vip_service import VipService


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
    return VipService(fortigate_manager, change_service)


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


class TestListVirtualIps:
    @pytest.mark.asyncio
    async def test_list_delegates(self, service, registered):
        result = await service.list_virtual_ips("test_device", vdom="root")
        registered.get_virtual_ips.assert_awaited_once_with(vdom="root")
        assert result is not None


class TestCreateVirtualIpPreview:
    @pytest.mark.asyncio
    async def test_create_previews_without_executing(self, service, registered):
        result = await service.create_virtual_ip("test_device", "vip1", "1.2.3.4", "10.0.0.1", "wan1")
        registered.create_virtual_ip.assert_not_awaited()
        assert "change_id" in result[0].text

    @pytest.mark.asyncio
    async def test_apply_with_all_optional_fields(self, service, change_service, registered):
        preview_result = await service.create_virtual_ip(
            "test_device", "vip1", "1.2.3.4", "10.0.0.1", "wan1",
            portforward="enable", protocol="tcp", extport="443", mappedport="8443",
        )
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_virtual_ip.assert_awaited_once_with(
            {
                "name": "vip1",
                "extip": "1.2.3.4",
                "mappedip": "10.0.0.1",
                "extintf": "wan1",
                "portforward": "enable",
                "protocol": "tcp",
                "extport": "443",
                "mappedport": "8443",
            },
            vdom=None,
        )

    @pytest.mark.asyncio
    async def test_apply_omits_absent_optional_fields(self, service, change_service, registered):
        preview_result = await service.create_virtual_ip("test_device", "vip2", "1.2.3.5", "10.0.0.2", "wan1")
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_virtual_ip.assert_awaited_once_with(
            {
                "name": "vip2",
                "extip": "1.2.3.5",
                "mappedip": "10.0.0.2",
                "extintf": "wan1",
                "portforward": "disable",
                "protocol": "tcp",
            },
            vdom=None,
        )

    @pytest.mark.asyncio
    async def test_create_missing_required_field_returns_error(self, service, registered):
        result = await service.create_virtual_ip("test_device", "", "1.2.3.4", "10.0.0.1", "wan1")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestUpdateGetDeleteVirtualIp:
    @pytest.mark.asyncio
    async def test_update_preview_then_apply(self, service, change_service, registered):
        vip_data = {"extip": "5.6.7.8"}
        preview_result = await service.update_virtual_ip("test_device", "vip1", vip_data)
        registered.update_virtual_ip.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.update_virtual_ip.assert_awaited_once_with("vip1", vip_data, vdom=None)

    @pytest.mark.asyncio
    async def test_get_detail_delegates(self, service, registered):
        result = await service.get_virtual_ip_detail("test_device", "vip1")
        registered.get_virtual_ip_detail.assert_awaited_once_with("vip1", vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_delete_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_virtual_ip("test_device", "vip1")
        registered.delete_virtual_ip.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.delete_virtual_ip.assert_awaited_once_with("vip1", vdom=None)


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.list_virtual_ips("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
