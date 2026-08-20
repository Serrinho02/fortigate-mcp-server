"""
Tests for RoutingService (Phase 2 migration of tools/routing.py, Phase 3
change-engine wiring).
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.routing_service import RoutingService


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
    return RoutingService(fortigate_manager, change_service)


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


class TestStaticRoutesPreview:
    @pytest.mark.asyncio
    async def test_list_static_routes_delegates(self, service, registered):
        result = await service.list_static_routes("test_device", vdom="root")
        registered.get_static_routes.assert_awaited_once_with(vdom="root")
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_static_route_apply_includes_device_when_given(self, service, change_service, registered):
        preview_result = await service.create_static_route(
            "test_device", "10.0.0.0/8", "192.168.1.1", device="port1"
        )
        registered.create_static_route.assert_not_awaited()
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_static_route.assert_awaited_once_with(
            {"dst": "10.0.0.0/8", "gateway": "192.168.1.1", "device": "port1"}, vdom=None
        )

    @pytest.mark.asyncio
    async def test_create_static_route_apply_omits_device_when_not_given(self, service, change_service, registered):
        preview_result = await service.create_static_route("test_device", "10.0.0.0/8", "192.168.1.1")
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_static_route.assert_awaited_once_with(
            {"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}, vdom=None
        )

    @pytest.mark.asyncio
    async def test_update_static_route_preview_then_apply(self, service, change_service, registered):
        route_data = {"dst": "10.0.0.0/8", "gateway": "192.168.1.2"}
        preview_result = await service.update_static_route("test_device", "1", route_data)
        registered.update_static_route.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.update_static_route.assert_awaited_once_with("1", route_data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_static_route_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_static_route("test_device", "1")
        registered.delete_static_route.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.delete_static_route.assert_awaited_once_with("1", vdom=None)

    @pytest.mark.asyncio
    async def test_get_static_route_detail_delegates(self, service, registered):
        result = await service.get_static_route_detail("test_device", "1")
        registered.get_static_route_detail.assert_awaited_once_with("1", vdom=None)
        assert result is not None


class TestRoutingTableAndInterfaces:
    """Read-only -- unaffected by the change engine."""

    @pytest.mark.asyncio
    async def test_get_routing_table_uses_dedicated_formatter(self, service, registered):
        result = await service.get_routing_table("test_device", vdom="root")
        registered.get_routing_table.assert_awaited_once_with(vdom="root")
        assert result is not None

    @pytest.mark.asyncio
    async def test_list_interfaces_delegates(self, service, registered):
        result = await service.list_interfaces("test_device")
        registered.get_interfaces.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_interface_status_delegates(self, service, registered):
        result = await service.get_interface_status("test_device", "port1")
        registered.get_interface_status.assert_awaited_once_with("port1", vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_interface_status_missing_name_returns_error(self, service, registered):
        result = await service.get_interface_status("test_device", "")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestInterfaceMutations:
    @pytest.mark.asyncio
    async def test_create_interface_preview_then_apply(self, service, change_service, registered):
        data = {"name": "vlan100", "type": "vlan", "interface": "port1", "vlanid": 100}
        preview_result = await service.create_interface("test_device", data)
        registered.create_interface.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_interface.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_interface_preview_then_apply(self, service, change_service, registered):
        data = {"ip": "10.0.0.1 255.255.255.0"}
        preview_result = await service.update_interface("test_device", "vlan100", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_interface.assert_awaited_once_with("vlan100", data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_interface_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_interface("test_device", "vlan100")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_interface.assert_awaited_once_with("vlan100", vdom=None)


class TestZoneMutations:
    @pytest.mark.asyncio
    async def test_list_zones_delegates(self, service, registered):
        result = await service.list_zones("test_device")
        registered.get_zones.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_zone_preview_then_apply(self, service, change_service, registered):
        data = {"name": "dmz", "interface": [{"interface-name": "port2"}]}
        preview_result = await service.create_zone("test_device", data)
        registered.create_zone.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_zone.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_zone_preview_then_apply(self, service, change_service, registered):
        data = {"interface": [{"interface-name": "port2"}, {"interface-name": "port3"}]}
        preview_result = await service.update_zone("test_device", "dmz", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_zone.assert_awaited_once_with("dmz", data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_zone_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_zone("test_device", "dmz")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_zone.assert_awaited_once_with("dmz", vdom=None)


class TestDhcpServerMutations:
    @pytest.mark.asyncio
    async def test_list_dhcp_servers_delegates(self, service, registered):
        result = await service.list_dhcp_servers("test_device")
        registered.get_dhcp_servers.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_dhcp_server_preview_then_apply(self, service, change_service, registered):
        data = {"interface": "vlan100", "ip-range": [{"start-ip": "10.0.0.10", "end-ip": "10.0.0.100"}]}
        preview_result = await service.create_dhcp_server("test_device", data)
        registered.create_dhcp_server.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_dhcp_server.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_dhcp_server_preview_then_apply(self, service, change_service, registered):
        data = {"default-gateway": "10.0.0.1"}
        preview_result = await service.update_dhcp_server("test_device", "1", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_dhcp_server.assert_awaited_once_with("1", data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_dhcp_server_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_dhcp_server("test_device", "1")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_dhcp_server.assert_awaited_once_with("1", vdom=None)


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_delete_static_route_blocked_in_safe_mode(self, fortigate_manager, session_factory, registered):
        safe_change_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.SAFE))
        service = RoutingService(fortigate_manager, safe_change_service)

        result = await service.delete_static_route("test_device", "1")

        assert "safe" in result[0].text.lower()
        registered.delete_static_route.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_interface_blocked_in_safe_mode(self, fortigate_manager, session_factory, registered):
        safe_change_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.SAFE))
        service = RoutingService(fortigate_manager, safe_change_service)

        result = await service.delete_interface("test_device", "vlan100")

        assert "safe" in result[0].text.lower()
        registered.delete_interface.assert_not_awaited()


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.list_static_routes("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
