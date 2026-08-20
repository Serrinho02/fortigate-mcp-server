"""
Shared base for the Phase 2 service classes.

Replaces `tools/base.py`'s repeated `try/except -> self._handle_error(...)`
boilerplate (copy-pasted ~30 times across `tools/*.py`) with a single
decorator, `@service_operation(name)`, applied once per method. Response
formatting and error categorization are intentionally duplicated from
`FortiGateTool` rather than imported from it: `tools/base.py` is deleted
once every domain has migrated (see roadmap Phase 2), so nothing in the
new `services/` package should depend on it.
"""
from __future__ import annotations

import functools
import json
import time
from typing import Any, Awaitable, Callable, List, Optional, TypeVar

from mcp.types import TextContent as Content

from src.fortigate_mcp.core.fortigate import FortiGateAPIError, FortiGateManager
from src.fortigate_mcp.core.logging import get_logger, log_tool_call
from src.fortigate_mcp.formatting import FortiGateFormatters

from ..adapters.base import FortinetProductAdapter
from ..infra.connection_manager import ConnectionManager
from .change_service import ChangePreview, ChangeService
from .device_resolution import resolve_adapter

F = TypeVar("F", bound=Callable[..., Awaitable[List[Content]]])


def service_operation(operation: str) -> Callable[[F], F]:
    """Wrap a `Service` method shaped `(self, device_id, *args, **kwargs)`:
    logs the call, and on any exception returns the same formatted error
    response `FortiGateTool._handle_error` used to produce, instead of
    letting the exception propagate."""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(self: "FortiGateServiceBase", device_id: str, *args: Any, **kwargs: Any):
            start = time.time()
            try:
                result = await func(self, device_id, *args, **kwargs)
                log_tool_call(self.logger, operation, device_id, True, (time.time() - start) * 1000)
                return result
            except Exception as e:  # noqa: BLE001 -- intentionally broad, mirrors tools/base.py
                log_tool_call(
                    self.logger, operation, device_id, False, (time.time() - start) * 1000, str(e)
                )
                return self._handle_error(operation, device_id, e)

        return wrapper  # type: ignore[return-value]

    return decorator


class FortiGateServiceBase:
    """Common device access + response formatting for every service.

    `change_service` is only needed by services with mutating methods
    (Policy/Network/Routing/Vip); DeviceService's add_device/remove_device
    act on the FortiGateManager's local registry rather than a live device
    resource, so they don't go through the change engine and can leave it
    as None.
    """

    def __init__(
        self,
        fortigate_manager: FortiGateManager,
        change_service: Optional[ChangeService] = None,
        connection_manager: Optional[ConnectionManager] = None,
    ):
        self.fortigate_manager = fortigate_manager
        self.change_service = change_service
        self.connection_manager = connection_manager
        self.logger = get_logger(f"services.{self.__class__.__name__.lower()}")

    async def _get_adapter(self, device_id: str) -> FortinetProductAdapter:
        """Resolve `device_id` to a live adapter -- tries the legacy
        FortiGateManager (config.json-backed) first, then falls back to the
        inventory DB via `connection_manager` if given and the id isn't
        found there. See device_resolution.py for why both exist.

        Raises:
            ValueError: not found in either system (or a more specific,
                actionable error surfaced from inventory resolution).
        """
        return await resolve_adapter(device_id, self.fortigate_manager, self.connection_manager)

    def _validate_required_params(self, **params: Any) -> None:
        for name, value in params.items():
            if value is None or (isinstance(value, str) and not value.strip()):
                raise ValueError(f"Parameter '{name}' is required")

    def _format_response(self, data: Any, resource_type: Optional[str] = None, **kwargs: Any) -> List[Content]:
        if resource_type == "devices":
            if isinstance(data, list):
                if not data:
                    return [Content(type="text", text="No FortiGate devices configured")]
                lines = ["**Registered FortiGate Devices**", ""]
                for device_id in data:
                    lines.append(f"  - {device_id}")
                return [Content(type="text", text="\n".join(lines))]
            return FortiGateFormatters.format_devices(data)
        elif resource_type == "device_status":
            if isinstance(data, tuple) and len(data) == 2:
                return FortiGateFormatters.format_device_status(data[0], data[1])
            return FortiGateFormatters.format_device_status("unknown", data)
        elif resource_type == "firewall_policies":
            return FortiGateFormatters.format_firewall_policies(data)
        elif resource_type == "firewall_policy_detail":
            device_id = kwargs.get("device_id", "unknown")
            address_objects = kwargs.get("address_objects")
            service_objects = kwargs.get("service_objects")
            return FortiGateFormatters.format_firewall_policy_detail(
                data, device_id, address_objects, service_objects
            )
        elif resource_type == "address_objects":
            return FortiGateFormatters.format_address_objects(data)
        elif resource_type == "service_objects":
            return FortiGateFormatters.format_service_objects(data)
        elif resource_type == "static_routes":
            return FortiGateFormatters.format_static_routes(data)
        elif resource_type == "interfaces":
            return FortiGateFormatters.format_interfaces(data)
        elif resource_type == "vdoms":
            return FortiGateFormatters.format_vdoms(data)
        elif resource_type == "virtual_ips":
            return FortiGateFormatters.format_virtual_ips(data)
        elif resource_type == "virtual_ip_detail":
            return FortiGateFormatters.format_virtual_ip_detail(data)
        elif resource_type == "interface_status":
            return FortiGateFormatters.format_json_response(data, "Interface Status")
        elif resource_type == "static_route_detail":
            return FortiGateFormatters.format_json_response(data, "Static Route Detail")
        else:
            return FortiGateFormatters.format_json_response(data)

    def _handle_error(self, operation: str, device_id: str, error: Exception) -> List[Content]:
        error_msg = str(error)
        self.logger.error(f"Failed to {operation} on device {device_id}: {error_msg}")

        if isinstance(error, FortiGateAPIError):
            if error.status_code == 401:
                error_msg = "Authentication failed. Check device credentials."
            elif error.status_code == 403:
                error_msg = "Permission denied. Insufficient privileges for this operation."
            elif error.status_code == 404:
                error_msg = "Resource not found. The specified item may not exist."
            elif error.status_code == 500:
                error_msg = "FortiGate internal server error. Check device status."
        elif "not found" in error_msg.lower():
            error_msg = "Resource not found. The specified item may not exist."
        elif "permission denied" in error_msg.lower():
            error_msg = "Permission denied. Check user privileges."
        elif "timeout" in error_msg.lower():
            error_msg = "Operation timed out. Check network connectivity."
        elif "connection" in error_msg.lower():
            error_msg = "Connection failed. Check device network settings."

        return FortiGateFormatters.format_error_response(operation, device_id, error_msg)

    def _format_operation_result(
        self,
        operation: str,
        device_id: str,
        success: bool,
        details: Optional[str] = None,
        error: Optional[str] = None,
    ) -> List[Content]:
        return FortiGateFormatters.format_operation_result(operation, device_id, success, details, error)

    def _format_connection_test(
        self, device_id: str, success: bool, error: Optional[str] = None
    ) -> List[Content]:
        return FortiGateFormatters.format_connection_test(device_id, success, error)

    def _format_change_preview(self, preview: ChangePreview) -> List[Content]:
        """Phase 3: every mutating tool now returns a preview instead of
        executing immediately -- this is the response shape for all of
        them. `change.apply(change_id)` is a separate, later tool call."""
        lines = [
            "Change proposed (not yet applied)",
            f"  change_id: {preview.change_id}",
            f"  operation: {preview.operation}",
            f"  resource: {preview.resource_type}",
            f"  device: {preview.device_id}",
        ]
        if preview.vdom:
            lines.append(f"  vdom: {preview.vdom}")
        lines.append("")
        lines.append("Diff:")
        lines.append(json.dumps(preview.diff, indent=2, default=str))
        lines.append("")
        lines.append(f'To apply this change, call change.apply(change_id="{preview.change_id}").')
        lines.append(f"This preview expires at {preview.expires_at.isoformat()} UTC.")
        return [Content(type="text", text="\n".join(lines))]

    def _format_analysis_result(self, title: str, data: Any) -> List[Content]:
        """Phase 4: analysis tools are read-only, so this is just a plain
        titled JSON dump -- no diff/change_id ceremony needed."""
        return [Content(type="text", text=f"{title}\n\n{json.dumps(data, indent=2, default=str)}")]

    def _format_document(self, content: str) -> List[Content]:
        """Phase 5: doc/diagram generators return ready-to-use source text
        (Markdown, Mermaid, PlantUML, drawio XML) -- returned verbatim, not
        JSON-wrapped, so it can be pasted straight into a renderer."""
        return [Content(type="text", text=content)]
