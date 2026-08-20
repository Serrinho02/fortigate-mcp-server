"""
FleetService -- multi-device operations (Phase 6): compare, search, sync,
replicate, and report across the inventory. Resolves devices via
ConnectionManager/the inventory DB (Customer -> Site -> Device), not the
legacy FortiGateManager the other Phase 2-5 services use -- fleet
operations are exactly the workload Phase 1's inventory/connection layer
was built for (a customer or site can genuinely have many devices; the
legacy FortiGateManager has no such grouping concept at all).

sync_objects/replicate_config safety note: they default to a dry-run plan
(zero adapter writes). Executing (confirm=True) still checks ModePolicy
first, but does NOT go through ChangeService's
ChangeRecord/PolicySnapshot/rollback machinery -- that model is built
around a single resource on a single device with a change_id to apply
later, and stretching it to "N objects across M devices" is a genuine
follow-up piece of work, not something to fake here.
"""
from __future__ import annotations

import json
from typing import Any, List, Optional

from mcp.types import TextContent as Content

from ..domain import fleet_compare
from ..domain.analysis import any_any, best_practice, duplicate, scoring, shadowed, unused_objects
from ..errors import (
    AmbiguousTargetError,
    CredentialNotProvisionedError,
    DeviceConnectionError,
    DeviceNotFoundError,
    ModeViolationError,
)
from ..infra.connection_manager import ConnectionManager
from . import change_dispatch
from .mode_policy import ModePolicy, OperationType

_RESOLUTION_ERRORS = (ValueError, AmbiguousTargetError, DeviceNotFoundError)
_CONNECTION_ERRORS = (CredentialNotProvisionedError, DeviceConnectionError)


class FleetService:
    def __init__(self, connection_manager: ConnectionManager, mode_policy: ModePolicy):
        self._connection_manager = connection_manager
        self._mode_policy = mode_policy

    def _error(self, message: str) -> List[Content]:
        return [Content(type="text", text=json.dumps({"error": message}, indent=2))]

    def _result(self, title: str, data: Any) -> List[Content]:
        return [Content(type="text", text=f"{title}\n\n{json.dumps(data, indent=2, default=str)}")]

    async def compare_devices(
        self,
        target_a: str,
        target_b: str,
        resource_type: str = "firewall_policy",
        vdom: Optional[str] = None,
    ) -> List[Content]:
        try:
            session_a = await self._connection_manager.connect(target_a, vdom=vdom)
            session_b = await self._connection_manager.connect(target_b, vdom=vdom)
        except (*_RESOLUTION_ERRORS, *_CONNECTION_ERRORS) as e:
            return self._error(str(e))

        try:
            items_a = await change_dispatch.list_all(session_a.adapter, resource_type, vdom)
            items_b = await change_dispatch.list_all(session_b.adapter, resource_type, vdom)
        except ValueError as e:
            return self._error(str(e))

        result = fleet_compare.compare_resource_lists(resource_type, items_a, items_b)
        result["device_a"] = session_a.device_name
        result["device_b"] = session_b.device_name
        return self._result("Fleet Comparison", result)

    async def search_object(
        self,
        object_name: str,
        resource_type: str = "address_object",
        target: Optional[str] = None,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        try:
            devices = (
                await self._connection_manager.resolve_target(target)
                if target
                else await self._connection_manager.list_all_devices()
            )
        except _RESOLUTION_ERRORS as e:
            return self._error(str(e))

        matches = []
        for device in devices:
            entry: dict[str, Any] = {
                "device": device.name,
                "customer": device.site.customer.name,
                "site": device.site.name,
            }
            try:
                session = await self._connection_manager.get_session(device, vdom=vdom)
            except _CONNECTION_ERRORS as e:
                entry["error"] = str(e)
                matches.append(entry)
                continue

            try:
                items = await change_dispatch.list_all(session.adapter, resource_type, vdom)
            except ValueError as e:
                return self._error(str(e))

            found = next(
                (
                    item
                    for item in items
                    if item.get("name") == object_name or str(item.get("policyid")) == object_name
                ),
                None,
            )
            entry["found"] = found is not None
            if found is not None:
                entry["object"] = found
            matches.append(entry)

        return self._result(
            "Fleet Object Search",
            {"object_name": object_name, "resource_type": resource_type, "matches": matches},
        )

    async def sync_objects(
        self,
        source_target: str,
        dest_target: str,
        resource_type: str = "address_object",
        vdom: Optional[str] = None,
        confirm: bool = False,
    ) -> List[Content]:
        try:
            source_session = await self._connection_manager.connect(source_target, vdom=vdom)
            dest_session = await self._connection_manager.connect(dest_target, vdom=vdom)
        except (*_RESOLUTION_ERRORS, *_CONNECTION_ERRORS) as e:
            return self._error(str(e))

        try:
            source_items = await change_dispatch.list_all(source_session.adapter, resource_type, vdom)
            dest_items = await change_dispatch.list_all(dest_session.adapter, resource_type, vdom)
        except ValueError as e:
            return self._error(str(e))

        dest_names = {item.get("name") for item in dest_items}
        missing = [item for item in source_items if item.get("name") not in dest_names]

        if not confirm:
            return self._result(
                "Fleet Sync Plan (dry run -- pass confirm=True to execute)",
                {
                    "source_device": source_session.device_name,
                    "dest_device": dest_session.device_name,
                    "resource_type": resource_type,
                    "objects_to_create": [item.get("name") for item in missing],
                },
            )

        try:
            self._mode_policy.check(OperationType.CREATE)
        except ModeViolationError as e:
            return self._error(str(e))

        results = []
        for item in missing:
            try:
                await change_dispatch.execute(dest_session.adapter, resource_type, "create", None, item, vdom)
                results.append({"name": item.get("name"), "status": "created"})
            except Exception as e:  # noqa: BLE001 -- one object's failure must not abort the rest
                results.append({"name": item.get("name"), "status": "failed", "error": str(e)})

        return self._result(
            "Fleet Sync Result",
            {
                "source_device": source_session.device_name,
                "dest_device": dest_session.device_name,
                "resource_type": resource_type,
                "results": results,
            },
        )

    async def replicate_config(
        self,
        source_target: str,
        dest_target: str,
        resource_types: Optional[list] = None,
        vdom: Optional[str] = None,
        confirm: bool = False,
    ) -> List[Content]:
        """Like sync_objects, but for every resource_type in `resource_types`
        (default: address + service objects) and every device `dest_target`
        resolves to (e.g. a whole site)."""
        resource_types = resource_types or ["address_object", "service_object"]

        try:
            source_session = await self._connection_manager.connect(source_target, vdom=vdom)
            dest_devices = await self._connection_manager.resolve_target(dest_target)
        except (*_RESOLUTION_ERRORS, *_CONNECTION_ERRORS) as e:
            return self._error(str(e))

        if confirm:
            try:
                self._mode_policy.check(OperationType.CREATE)
            except ModeViolationError as e:
                return self._error(str(e))

        device_reports = []
        for device in dest_devices:
            if device.name == source_session.device_name:
                continue  # skip replicating a device onto itself if it's in the resolved scope

            try:
                dest_session = await self._connection_manager.get_session(device, vdom=vdom)
            except _CONNECTION_ERRORS as e:
                device_reports.append({"device": device.name, "error": str(e)})
                continue

            per_resource: dict[str, Any] = {}
            for resource_type in resource_types:
                try:
                    source_items = await change_dispatch.list_all(source_session.adapter, resource_type, vdom)
                    dest_items = await change_dispatch.list_all(dest_session.adapter, resource_type, vdom)
                except ValueError as e:
                    per_resource[resource_type] = {"error": str(e)}
                    continue

                dest_names = {item.get("name") for item in dest_items}
                missing = [item for item in source_items if item.get("name") not in dest_names]

                if not confirm:
                    per_resource[resource_type] = {
                        "objects_to_create": [item.get("name") for item in missing]
                    }
                    continue

                results = []
                for item in missing:
                    try:
                        await change_dispatch.execute(
                            dest_session.adapter, resource_type, "create", None, item, vdom
                        )
                        results.append({"name": item.get("name"), "status": "created"})
                    except Exception as e:  # noqa: BLE001
                        results.append({"name": item.get("name"), "status": "failed", "error": str(e)})
                per_resource[resource_type] = {"results": results}

            device_reports.append({"device": device.name, **per_resource})

        title = (
            "Fleet Replicate Result"
            if confirm
            else "Fleet Replicate Plan (dry run -- pass confirm=True to execute)"
        )
        return self._result(title, {"source_device": source_session.device_name, "devices": device_reports})

    async def report(self, target: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            devices = await self._connection_manager.resolve_target(target)
        except _RESOLUTION_ERRORS as e:
            return self._error(str(e))

        device_reports = []
        for device in devices:
            entry: dict[str, Any] = {
                "device": device.name,
                "customer": device.site.customer.name,
                "site": device.site.name,
            }
            try:
                session = await self._connection_manager.get_session(device, vdom=vdom)
            except _CONNECTION_ERRORS as e:
                entry["error"] = str(e)
                device_reports.append(entry)
                continue

            policies = await change_dispatch.list_all(session.adapter, "firewall_policy", vdom)
            addresses = await change_dispatch.list_all(session.adapter, "address_object", vdom)
            services = await change_dispatch.list_all(session.adapter, "service_object", vdom)
            vips = await change_dispatch.list_all(session.adapter, "virtual_ip", vdom)

            any_any_findings = any_any.find_any_any_policies(policies)
            shadowed_findings = shadowed.find_shadowed_policies(policies)
            duplicate_findings = duplicate.find_duplicate_policies(policies)
            unused_count = (
                len(unused_objects.find_unused(addresses, policies, ("srcaddr", "dstaddr")))
                + len(unused_objects.find_unused(services, policies, ("service",)))
                + len(unused_objects.find_unused(vips, policies, ("srcaddr", "dstaddr")))
            )
            best_practice_findings = best_practice.check_best_practices(policies)
            score = scoring.score_security(
                any_any_count=len(any_any_findings),
                shadowed_count=len(shadowed_findings),
                duplicate_count=len(duplicate_findings),
                unused_count=unused_count,
                best_practice_issues=best_practice_findings,
            )

            entry.update({"policy_count": len(policies), "security_score": score})
            device_reports.append(entry)

        scored_entries = [d for d in device_reports if "security_score" in d]
        scores = [d["security_score"]["score"] for d in scored_entries]
        summary = {
            "device_count": len(devices),
            "reachable_device_count": len(scored_entries),
            "average_score": round(sum(scores) / len(scores), 1) if scores else None,
        }

        return self._result("Fleet Report", {"summary": summary, "devices": device_reports})
