"""
NetworkService -- replaces tools/network.py.

Note: `create_address_object` faithfully preserves a pre-existing quirk
from the legacy tool -- it always writes the value into a `subnet` field
regardless of `address_type`, so `iprange`/`fqdn` types don't actually
produce a correct payload. Not fixed here: Phase 2 is a behavior-preserving
refactor, not a bug-fix pass.

Phase 3: create_address_object/create_service_object now preview instead
of executing immediately, like every other mutating service (see
PolicyService).
"""
from __future__ import annotations

from typing import List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class NetworkService(FortiGateServiceBase):
    @service_operation("list address objects")
    async def list_address_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        addresses_data = await adapter.list_address_objects(vdom=vdom)
        return self._format_response(addresses_data, "address_objects")

    @service_operation("create address object")
    async def create_address_object(
        self,
        device_id: str,
        name: str,
        address_type: str,
        address: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(name=name, address_type=address_type, address=address)

        address_data = {"name": name, "type": address_type, "subnet": address}

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="address_object",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=address_data,
        )
        return self._format_change_preview(preview)

    @service_operation("list service objects")
    async def list_service_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        services_data = await adapter.list_service_objects(vdom=vdom)
        return self._format_response(services_data, "service_objects")

    @service_operation("create service object")
    async def create_service_object(
        self,
        device_id: str,
        name: str,
        service_type: str,
        protocol: str,
        port: Optional[str] = None,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(name=name, service_type=service_type, protocol=protocol)

        service_data = {"name": name, "type": service_type, "protocol": protocol}
        if port:
            service_data["port"] = port

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="service_object",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=service_data,
        )
        return self._format_change_preview(preview)
