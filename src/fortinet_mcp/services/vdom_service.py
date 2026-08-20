"""
VdomService -- VDOM lifecycle (create/delete) and inter-VDOM links. Part of
the "configure a FortiGate from zero" effort (system_service.py's Phase A
sibling for multi-tenant topology).

VDOM listing itself stays in DeviceService.discover_vdoms (added in an
earlier phase) -- not duplicated here.

Both VDOM and vdom-link objects are global, not scoped to any one VDOM
(there's no "vdom" query parameter that means anything for them -- see
adapters/base.py's Protocol docstring for why the underlying adapter
methods still accept-but-ignore a vdom kwarg, purely so change_dispatch's
generic execute()/fetch_current() can dispatch to them like any other
resource type). So, unlike every other service in this codebase, none of
these methods take a `vdom` parameter from the caller.

Operational warning (surfaced primarily in the MCP tool description, see
mcp/tools/vdom_tools.py, since that's what Claude actually reads before
calling): creating an additional VDOM requires the device to already be in
multi-vdom mode (system_update_global with vdom-mode: multi-vdom -- see
SystemService). Enabling multi-vdom mode on a device that has never had it
enabled can require a reboot or cause a temporary loss of management
connectivity on real hardware; this varies by firmware/platform and should
be verified against the target device rather than assumed.
"""
from __future__ import annotations

from typing import Any, Dict, List

from mcp.types import TextContent as Content

from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class VdomService(FortiGateServiceBase):
    @service_operation("create VDOM")
    async def create_vdom(self, device_id: str, vdom_data: Dict[str, Any]) -> List[Content]:
        self._validate_required_params(vdom_data=vdom_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=None,
            resource_type="vdom",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=vdom_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete VDOM")
    async def delete_vdom(self, device_id: str, name: str) -> List[Content]:
        self._validate_required_params(name=name)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=None,
            resource_type="vdom",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    @service_operation("list inter-VDOM links")
    async def list_vdom_links(self, device_id: str) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.list_vdom_links()
        return self._format_response(data, "vdom_links")

    @service_operation("create inter-VDOM link")
    async def create_vdom_link(self, device_id: str, link_data: Dict[str, Any]) -> List[Content]:
        self._validate_required_params(link_data=link_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=None,
            resource_type="vdom_link",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=link_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete inter-VDOM link")
    async def delete_vdom_link(self, device_id: str, name: str) -> List[Content]:
        self._validate_required_params(name=name)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=None,
            resource_type="vdom_link",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)
