"""
VipService -- replaces tools/virtual_ip.py.

Phase 3: create/update/delete_virtual_ip now preview instead of executing
immediately, like every other mutating service.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class VipService(FortiGateServiceBase):
    @service_operation("list virtual IPs")
    async def list_virtual_ips(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        vips_data = await adapter.list_virtual_ips(vdom=vdom)
        return self._format_response(vips_data, "virtual_ips")

    @service_operation("create virtual IP")
    async def create_virtual_ip(
        self,
        device_id: str,
        name: str,
        extip: str,
        mappedip: str,
        extintf: str,
        portforward: str = "disable",
        protocol: str = "tcp",
        extport: Optional[str] = None,
        mappedport: Optional[str] = None,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(name=name, extip=extip, mappedip=mappedip, extintf=extintf)

        vip_data = {
            "name": name,
            "extip": extip,
            "mappedip": mappedip,
            "extintf": extintf,
            "portforward": portforward,
        }
        if protocol:
            vip_data["protocol"] = protocol
        if extport:
            vip_data["extport"] = extport
        if mappedport:
            vip_data["mappedport"] = mappedport

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="virtual_ip",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=vip_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update virtual IP")
    async def update_virtual_ip(
        self, device_id: str, name: str, vip_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="virtual_ip",
            operation=OperationType.UPDATE,
            resource_id=name,
            proposed_data=vip_data,
        )
        return self._format_change_preview(preview)

    @service_operation("get virtual IP detail")
    async def get_virtual_ip_detail(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)

        adapter = await self._get_adapter(device_id)
        vip_data = await adapter.get_virtual_ip(name, vdom=vdom)
        return self._format_response(vip_data, "virtual_ip_detail")

    @service_operation("delete virtual IP")
    async def delete_virtual_ip(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="virtual_ip",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)
