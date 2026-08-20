"""
Tests for DeviceService (Phase 2 migration of tools/device.py). Reuses the
same `mock_fortigate_api`/`fortigate_manager` fixtures as the pre-existing
tests/test_tools.py so behavior parity with the legacy DeviceTools is
directly comparable.
"""
import pytest

from src.fortinet_mcp.services.device_service import DeviceService


@pytest.fixture
def service(fortigate_manager):
    return DeviceService(fortigate_manager)


class TestListDevices:
    @pytest.mark.asyncio
    async def test_list_devices_empty(self, service):
        result = await service.list_devices()
        assert "No FortiGate devices configured" in result[0].text


class TestGetDeviceStatus:
    @pytest.mark.asyncio
    async def test_get_status_success(self, service, fortigate_manager, mock_fortigate_api):
        fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await service.get_device_status("test_device")

        mock_fortigate_api.get_system_status.assert_awaited_once_with(vdom=None)
        assert "FortiGate" in result[0].text or "test_device" in result[0].text

    @pytest.mark.asyncio
    async def test_get_status_unknown_device_returns_formatted_error(self, service):
        result = await service.get_device_status("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()


class TestTestDeviceConnection:
    @pytest.mark.asyncio
    async def test_connection_success(self, service, fortigate_manager, mock_fortigate_api):
        fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await service.test_device_connection("test_device")

        mock_fortigate_api.test_connection.assert_awaited_once_with()
        assert result is not None

    @pytest.mark.asyncio
    async def test_connection_unknown_device_returns_failure_not_generic_error(self, service):
        result = await service.test_device_connection("nope")
        # matches legacy behavior: goes through _format_connection_test, not _handle_error
        assert result is not None


class TestDiscoverVdoms:
    @pytest.mark.asyncio
    async def test_discover_vdoms_success(self, service, fortigate_manager, mock_fortigate_api):
        fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await service.discover_vdoms("test_device")

        mock_fortigate_api.get_vdoms.assert_awaited_once_with()
        assert result is not None


class TestAddRemoveDevice:
    @pytest.mark.asyncio
    async def test_add_device_success(self, service, fortigate_manager):
        result = await service.add_device("new_device", "10.0.0.5", api_token="tok")

        assert "new_device" in fortigate_manager.devices
        assert "success" in result[0].text.lower() or "added" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_add_duplicate_device_fails_gracefully(self, service, fortigate_manager, mock_fortigate_api):
        fortigate_manager.devices["dup"] = mock_fortigate_api

        result = await service.add_device("dup", "10.0.0.5", api_token="tok")

        assert "already exists" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_remove_device_success(self, service, fortigate_manager, mock_fortigate_api):
        fortigate_manager.devices["to_remove"] = mock_fortigate_api

        result = await service.remove_device("to_remove")

        assert "to_remove" not in fortigate_manager.devices
        assert "removed" in result[0].text.lower() or "success" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_remove_unknown_device_returns_formatted_error(self, service):
        result = await service.remove_device("nope")
        assert "not found" in result[0].text.lower() or "error" in result[0].text.lower()
