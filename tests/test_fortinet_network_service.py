"""
Tests for NetworkService (Phase 2 migration of tools/network.py, Phase 3
change-engine wiring).
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.network_service import NetworkService


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
    return NetworkService(fortigate_manager, change_service)


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


class TestAddressObjects:
    @pytest.mark.asyncio
    async def test_list_address_objects_delegates(self, service, registered):
        result = await service.list_address_objects("test_device", vdom="root")
        registered.get_address_objects.assert_awaited_once_with(vdom="root")
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_address_object_previews_without_executing(self, service, registered):
        result = await service.create_address_object("test_device", "web1", "ipmask", "10.0.0.0/24")
        registered.create_address_object.assert_not_awaited()
        assert "change_id" in result[0].text

    @pytest.mark.asyncio
    async def test_create_address_object_apply_builds_subnet_payload(self, service, change_service, registered):
        preview_result = await service.create_address_object("test_device", "web1", "ipmask", "10.0.0.0/24")
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_address_object.assert_awaited_once_with(
            {"name": "web1", "type": "ipmask", "subnet": "10.0.0.0/24"}, vdom=None
        )

    @pytest.mark.asyncio
    async def test_create_address_object_missing_name_returns_error(self, service, registered):
        result = await service.create_address_object("test_device", "", "ipmask", "10.0.0.0/24")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestServiceObjects:
    @pytest.mark.asyncio
    async def test_list_service_objects_delegates(self, service, registered):
        result = await service.list_service_objects("test_device")
        registered.get_service_objects.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_service_object_apply_includes_port_when_given(self, service, change_service, registered):
        preview_result = await service.create_service_object(
            "test_device", "HTTP-ALT", "TCP/UDP/SCTP", "TCP", port="8080"
        )
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_service_object.assert_awaited_once_with(
            {"name": "HTTP-ALT", "type": "TCP/UDP/SCTP", "protocol": "TCP", "port": "8080"}, vdom=None
        )

    @pytest.mark.asyncio
    async def test_create_service_object_apply_omits_port_when_not_given(self, service, change_service, registered):
        preview_result = await service.create_service_object("test_device", "ANY-TCP", "TCP/UDP/SCTP", "TCP")
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_service_object.assert_awaited_once_with(
            {"name": "ANY-TCP", "type": "TCP/UDP/SCTP", "protocol": "TCP"}, vdom=None
        )


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_create_address_object_blocked_in_read_only_mode(
        self, fortigate_manager, session_factory, registered
    ):
        read_only_change_service = ChangeService(
            fortigate_manager, session_factory, ModePolicy(OperatingMode.READ_ONLY)
        )
        service = NetworkService(fortigate_manager, read_only_change_service)

        result = await service.create_address_object("test_device", "web1", "ipmask", "10.0.0.0/24")

        assert "read_only" in result[0].text.lower()
        registered.create_address_object.assert_not_awaited()


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.list_address_objects("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
