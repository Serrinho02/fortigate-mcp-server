"""
Tests for VpnService: IPsec tunnel CRUD (through the real change engine,
like PolicyService) plus read-only IPsec/SSL VPN status visibility.
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.vpn_service import VpnService


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
    return VpnService(fortigate_manager, change_service)


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


class TestListAndDetailIpsecTunnels:
    @pytest.mark.asyncio
    async def test_list_ipsec_tunnels_delegates(self, service, registered):
        result = await service.list_ipsec_tunnels("test_device", vdom="root")
        registered.get_ipsec_phase1_list.assert_awaited_once_with(vdom="root")
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_ipsec_tunnel_detail_delegates(self, service, registered):
        result = await service.get_ipsec_tunnel_detail("test_device", "tunnel1")
        registered.get_ipsec_phase1_detail.assert_awaited_once_with("tunnel1", vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_ipsec_tunnel_detail_missing_name_returns_error(self, service, registered):
        result = await service.get_ipsec_tunnel_detail("test_device", "")
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestCreateIpsecTunnelPreview:
    @pytest.mark.asyncio
    async def test_create_previews_without_executing(self, service, registered):
        tunnel_data = {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}
        result = await service.create_ipsec_tunnel("test_device", tunnel_data)
        registered.create_ipsec_phase1.assert_not_awaited()
        assert "change_id" in result[0].text

    @pytest.mark.asyncio
    async def test_create_preview_then_apply_executes(self, service, change_service, registered):
        tunnel_data = {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1", "psksecret": "s3cr3t"}
        preview_result = await service.create_ipsec_tunnel("test_device", tunnel_data)
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.create_ipsec_phase1.assert_awaited_once_with(tunnel_data, vdom=None)

    @pytest.mark.asyncio
    async def test_create_missing_data_returns_error(self, service, registered):
        result = await service.create_ipsec_tunnel("test_device", None)
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestUpdateDeleteIpsecTunnel:
    @pytest.mark.asyncio
    async def test_update_preview_then_apply(self, service, change_service, registered):
        update_data = {"remote-gw": "203.0.113.9"}
        preview_result = await service.update_ipsec_tunnel("test_device", "tunnel1", update_data)
        registered.update_ipsec_phase1.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.update_ipsec_phase1.assert_awaited_once_with("tunnel1", update_data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_ipsec_tunnel("test_device", "tunnel1")
        registered.delete_ipsec_phase1.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.delete_ipsec_phase1.assert_awaited_once_with("tunnel1", vdom=None)


class TestIpsecPhase2:
    @pytest.mark.asyncio
    async def test_list_phase2_delegates(self, service, registered):
        result = await service.list_ipsec_phase2("test_device")
        registered.get_ipsec_phase2_list.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_phase2_preview_then_apply(self, service, change_service, registered):
        phase2_data = {"name": "selector1", "phase1name": "tunnel1", "src-subnet": "10.0.0.0/24"}
        preview_result = await service.create_ipsec_phase2("test_device", phase2_data)
        registered.create_ipsec_phase2.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_ipsec_phase2.assert_awaited_once_with(phase2_data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_phase2_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_ipsec_phase2("test_device", "selector1")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_ipsec_phase2.assert_awaited_once_with("selector1", vdom=None)


class TestReadOnlyStatusAndSslVpn:
    @pytest.mark.asyncio
    async def test_get_ipsec_status_delegates(self, service, registered):
        result = await service.get_ipsec_status("test_device", vdom="root")
        registered.get_ipsec_tunnel_status.assert_awaited_once_with(vdom="root")
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_ssl_vpn_settings_delegates(self, service, registered):
        result = await service.get_ssl_vpn_settings("test_device")
        registered.get_ssl_vpn_settings.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_list_ssl_vpn_sessions_delegates(self, service, registered):
        result = await service.list_ssl_vpn_sessions("test_device")
        registered.get_ssl_vpn_sessions.assert_awaited_once_with(vdom=None)
        assert result is not None


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_create_tunnel_blocked_in_read_only_mode(self, fortigate_manager, session_factory, registered):
        read_only_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.READ_ONLY))
        service = VpnService(fortigate_manager, read_only_service)

        result = await service.create_ipsec_tunnel(
            "test_device", {"name": "tunnel1", "interface": "wan1", "remote-gw": "203.0.113.1"}
        )

        assert "read_only" in result[0].text.lower()
        registered.create_ipsec_phase1.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_tunnel_blocked_in_safe_mode(self, fortigate_manager, session_factory, registered):
        safe_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.SAFE))
        service = VpnService(fortigate_manager, safe_service)

        result = await service.delete_ipsec_tunnel("test_device", "tunnel1")

        assert "safe" in result[0].text.lower()
        registered.delete_ipsec_phase1.assert_not_awaited()


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.list_ipsec_tunnels("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
