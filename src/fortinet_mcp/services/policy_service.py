"""
PolicyService -- replaces tools/firewall.py.

Phase 3: create/update/delete no longer execute immediately. Each now
calls `ChangeService.preview(...)` and returns a diff + change_id;
`change.apply(change_id)` is a separate tool call that actually runs the
operation (see architecture plan §9 -- every mode requires preview+apply,
with no single-shot fast path even in FULL).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class PolicyService(FortiGateServiceBase):
    @service_operation("list firewall policies")
    async def list_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        policies_data = await adapter.list_policies(vdom=vdom)
        return self._format_response(policies_data, "firewall_policies")

    @service_operation("create firewall policy")
    async def create_policy(
        self, device_id: str, policy_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(policy_data=policy_data)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="firewall_policy",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=policy_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update firewall policy")
    async def update_policy(
        self,
        device_id: str,
        policy_id: str,
        policy_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="firewall_policy",
            operation=OperationType.UPDATE,
            resource_id=policy_id,
            proposed_data=policy_data,
        )
        return self._format_change_preview(preview)

    @service_operation("get firewall policy detail")
    async def get_policy_detail(
        self, device_id: str, policy_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(policy_id=policy_id)

        adapter = await self._get_adapter(device_id)
        policy_data = await adapter.get_policy(policy_id, vdom=vdom)

        try:
            address_objects = await adapter.list_address_objects(vdom=vdom)
        except Exception:
            address_objects = None

        try:
            service_objects = await adapter.list_service_objects(vdom=vdom)
        except Exception:
            service_objects = None

        return self._format_response(
            policy_data,
            "firewall_policy_detail",
            device_id=device_id,
            address_objects=address_objects,
            service_objects=service_objects,
        )

    @service_operation("delete firewall policy")
    async def delete_policy(
        self, device_id: str, policy_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(policy_id=policy_id)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="firewall_policy",
            operation=OperationType.DELETE,
            resource_id=policy_id,
            proposed_data=None,
        )
        return self._format_change_preview(preview)
