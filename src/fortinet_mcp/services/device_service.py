"""
DeviceService -- replaces tools/device.py.

`list_devices`/`add_device`/`remove_device` operate on the legacy
FortiGateManager's device registry directly (no per-device adapter
involved); `get_device_status`/`test_device_connection`/`discover_vdoms`
go through a FortiOSAdapter, per Phase 2's "Service sits between tool and
adapter" goal.
"""
from __future__ import annotations

from typing import List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateServiceBase, service_operation


class DeviceService(FortiGateServiceBase):
    async def list_devices(self) -> List[Content]:
        try:
            devices_info = self.fortigate_manager.list_devices()
            return self._format_response(devices_info, "devices")
        except Exception as e:
            return self._handle_error("list devices", "all", e)

    @service_operation("get device status")
    async def get_device_status(self, device_id: str) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        status_data = await adapter.get_status()
        return self._format_response((device_id, status_data), "device_status")

    async def test_device_connection(self, device_id: str) -> List[Content]:
        try:
            adapter = await self._get_adapter(device_id)
            success = await adapter.test_connection()
            return self._format_connection_test(device_id, success)
        except Exception as e:
            return self._format_connection_test(device_id, False, str(e))

    @service_operation("discover VDOMs")
    async def discover_vdoms(self, device_id: str) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        vdoms_data = await adapter.list_vdoms()
        return self._format_response(vdoms_data, "vdoms")

    @service_operation("add device")
    async def add_device(
        self,
        device_id: str,
        host: str,
        port: int = 443,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_token: Optional[str] = None,
        vdom: str = "root",
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> List[Content]:
        self._validate_required_params(device_id=device_id, host=host)

        if device_id in self.fortigate_manager.devices:
            return self._format_operation_result(
                "add device", device_id, False, error=f"Device '{device_id}' already exists"
            )

        self.fortigate_manager.add_device(
            device_id=device_id,
            host=host,
            port=port,
            username=username,
            password=password,
            api_token=api_token,
            vdom=vdom,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        return self._format_operation_result(
            "add device", device_id, True, f"Device '{device_id}' added successfully"
        )

    @service_operation("remove device")
    async def remove_device(self, device_id: str) -> List[Content]:
        await self.fortigate_manager.remove_device(device_id)
        return self._format_operation_result(
            "remove device", device_id, True, f"Device '{device_id}' removed successfully"
        )
