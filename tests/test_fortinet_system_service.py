"""
Tests for SystemService: DNS/NTP/syslog/SNMP/global/admin/HA -- singleton
gets go straight to the adapter, every mutation (including singleton
updates) goes through the real change engine (preview -> apply), exactly
like PolicyService/VpnService.
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.system_service import SystemService


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
    return SystemService(fortigate_manager, change_service)


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


class TestDns:
    @pytest.mark.asyncio
    async def test_get_dns_delegates(self, service, registered):
        result = await service.get_dns("test_device", vdom="root")
        registered.get_dns_settings.assert_awaited_once_with(vdom="root")
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_dns_previews_without_executing(self, service, registered):
        result = await service.update_dns("test_device", {"primary": "1.1.1.1"})
        registered.update_dns_settings.assert_not_awaited()
        assert "change_id" in result[0].text

    @pytest.mark.asyncio
    async def test_update_dns_preview_then_apply_executes(self, service, change_service, registered):
        dns_data = {"primary": "1.1.1.1", "secondary": "1.0.0.1"}
        preview_result = await service.update_dns("test_device", dns_data)
        change_id = _change_id_from(preview_result)

        await change_service.apply(change_id)

        registered.update_dns_settings.assert_awaited_once_with(dns_data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_dns_missing_data_returns_error(self, service, registered):
        result = await service.update_dns("test_device", None)
        assert "required" in result[0].text.lower() or "error" in result[0].text.lower()


class TestNtp:
    @pytest.mark.asyncio
    async def test_get_ntp_delegates(self, service, registered):
        result = await service.get_ntp("test_device")
        registered.get_ntp_settings.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_ntp_preview_then_apply(self, service, change_service, registered):
        ntp_data = {"ntpsync": "enable", "server": "pool.ntp.org"}
        preview_result = await service.update_ntp("test_device", ntp_data)
        registered.update_ntp_settings.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.update_ntp_settings.assert_awaited_once_with(ntp_data, vdom=None)


class TestSyslog:
    @pytest.mark.asyncio
    async def test_get_syslog_delegates(self, service, registered):
        result = await service.get_syslog("test_device")
        registered.get_syslog_settings.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_syslog_preview_then_apply(self, service, change_service, registered):
        syslog_data = {"status": "enable", "server": "10.0.0.50"}
        preview_result = await service.update_syslog("test_device", syslog_data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_syslog_settings.assert_awaited_once_with(syslog_data, vdom=None)


class TestSnmp:
    @pytest.mark.asyncio
    async def test_get_sysinfo_delegates(self, service, registered):
        result = await service.get_snmp_sysinfo("test_device")
        registered.get_snmp_sysinfo.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_sysinfo_preview_then_apply(self, service, change_service, registered):
        data = {"status": "enable", "description": "core-fw"}
        preview_result = await service.update_snmp_sysinfo("test_device", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_snmp_sysinfo.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_list_communities_delegates(self, service, registered):
        result = await service.list_snmp_communities("test_device")
        registered.get_snmp_communities.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_community_preview_then_apply(self, service, change_service, registered):
        data = {"name": "monitoring", "hosts": [{"ip": "10.0.0.5/32"}]}
        preview_result = await service.create_snmp_community("test_device", data)
        registered.create_snmp_community.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_snmp_community.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_community_preview_then_apply(self, service, change_service, registered):
        data = {"hosts": [{"ip": "10.0.0.9/32"}]}
        preview_result = await service.update_snmp_community("test_device", "1", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_snmp_community.assert_awaited_once_with("1", data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_community_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_snmp_community("test_device", "1")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_snmp_community.assert_awaited_once_with("1", vdom=None)


class TestGlobalSettings:
    @pytest.mark.asyncio
    async def test_get_global_settings_delegates(self, service, registered):
        result = await service.get_global_settings("test_device")
        registered.get_system_global.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_global_settings_preview_then_apply(self, service, change_service, registered):
        data = {"hostname": "CDM-OBM-HUB-FW01"}
        preview_result = await service.update_global_settings("test_device", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_system_global.assert_awaited_once_with(data, vdom=None)


class TestAdmins:
    @pytest.mark.asyncio
    async def test_list_admins_delegates(self, service, registered):
        result = await service.list_admins("test_device")
        registered.list_admins.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_create_admin_preview_then_apply(self, service, change_service, registered):
        data = {"name": "svc-account", "password": "s3cr3t", "accprofile": "super_admin"}
        preview_result = await service.create_admin("test_device", data)
        registered.create_admin.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.create_admin.assert_awaited_once_with(data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_admin_preview_then_apply(self, service, change_service, registered):
        data = {"accprofile": "read_only"}
        preview_result = await service.update_admin("test_device", "svc-account", data)
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.update_admin.assert_awaited_once_with("svc-account", data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_admin_preview_then_apply(self, service, change_service, registered):
        preview_result = await service.delete_admin("test_device", "svc-account")
        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)
        registered.delete_admin.assert_awaited_once_with("svc-account", vdom=None)


class TestHaConfig:
    @pytest.mark.asyncio
    async def test_get_ha_config_delegates(self, service, registered):
        result = await service.get_ha_config("test_device")
        registered.get_ha_config.assert_awaited_once_with(vdom=None)
        assert result is not None

    @pytest.mark.asyncio
    async def test_update_ha_config_preview_then_apply(self, service, change_service, registered):
        data = {"mode": "a-p", "group-id": 10, "password": "s3cr3t"}
        preview_result = await service.update_ha_config("test_device", data)
        registered.update_ha_config.assert_not_awaited()

        change_id = _change_id_from(preview_result)
        await change_service.apply(change_id)

        registered.update_ha_config.assert_awaited_once_with(data, vdom=None)


class TestModeEnforcement:
    @pytest.mark.asyncio
    async def test_update_dns_blocked_in_read_only_mode(self, fortigate_manager, session_factory, registered):
        read_only_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.READ_ONLY))
        service = SystemService(fortigate_manager, read_only_service)

        result = await service.update_dns("test_device", {"primary": "1.1.1.1"})

        assert "read_only" in result[0].text.lower()
        registered.update_dns_settings.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_admin_blocked_in_safe_mode(self, fortigate_manager, session_factory, registered):
        safe_service = ChangeService(fortigate_manager, session_factory, ModePolicy(OperatingMode.SAFE))
        service = SystemService(fortigate_manager, safe_service)

        result = await service.delete_admin("test_device", "svc-account")

        assert "safe" in result[0].text.lower()
        registered.delete_admin.assert_not_awaited()


class TestUnknownDevice:
    @pytest.mark.asyncio
    async def test_operations_on_unknown_device_return_formatted_error(self, service):
        result = await service.get_dns("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
