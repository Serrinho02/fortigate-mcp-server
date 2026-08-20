"""
RoutingService -- replaces tools/routing.py.

Phase 3: create/update/delete_static_route now preview instead of
executing immediately, like every other mutating service.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from src.fortigate_mcp.formatting import FortiGateFormatters

from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class RoutingService(FortiGateServiceBase):
    @service_operation("list static routes")
    async def list_static_routes(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        routes_data = await adapter.list_static_routes(vdom=vdom)
        return self._format_response(routes_data, "static_routes")

    @service_operation("create static route")
    async def create_static_route(
        self,
        device_id: str,
        dst: str,
        gateway: str,
        device: Optional[str] = None,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(dst=dst, gateway=gateway)

        route_data = {"dst": dst, "gateway": gateway}
        if device:
            route_data["device"] = device

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="static_route",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=route_data,
        )
        return self._format_change_preview(preview)

    @service_operation("get routing table")
    async def get_routing_table(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        routing_data = await adapter.get_routing_table(vdom=vdom)
        return FortiGateFormatters.format_routing_table(routing_data)

    @service_operation("list interfaces")
    async def list_interfaces(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        interfaces_data = await adapter.list_interfaces(vdom=vdom)
        return self._format_response(interfaces_data, "interfaces")

    @service_operation("get interface status")
    async def get_interface_status(
        self, device_id: str, interface_name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(interface_name=interface_name)

        adapter = await self._get_adapter(device_id)
        interface_data = await adapter.get_interface_status(interface_name, vdom=vdom)
        return self._format_response((interface_name, interface_data), "interface_status")

    @service_operation("update static route")
    async def update_static_route(
        self, device_id: str, route_id: str, route_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(route_id=route_id)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="static_route",
            operation=OperationType.UPDATE,
            resource_id=route_id,
            proposed_data=route_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete static route")
    async def delete_static_route(
        self, device_id: str, route_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(route_id=route_id)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="static_route",
            operation=OperationType.DELETE,
            resource_id=route_id,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    @service_operation("get static route detail")
    async def get_static_route_detail(
        self, device_id: str, route_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(route_id=route_id)

        adapter = await self._get_adapter(device_id)
        route_data = await adapter.get_static_route(route_id, vdom=vdom)
        return self._format_response(route_data, "static_route_detail")

    # --- Interfaces (Phase C: VLAN sub-interfaces, loopbacks, vdom-link members) --

    @service_operation("create interface")
    async def create_interface(
        self, device_id: str, interface_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(interface_data=interface_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="interface",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=interface_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update interface")
    async def update_interface(
        self,
        device_id: str,
        name: str,
        interface_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(name=name, interface_data=interface_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="interface",
            operation=OperationType.UPDATE,
            resource_id=name,
            proposed_data=interface_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete interface")
    async def delete_interface(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="interface",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    # --- Zones -------------------------------------------------------------------

    @service_operation("list zones")
    async def list_zones(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.list_zones(vdom=vdom)
        return self._format_response(data, "zones")

    @service_operation("create zone")
    async def create_zone(
        self, device_id: str, zone_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(zone_data=zone_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="zone",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=zone_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update zone")
    async def update_zone(
        self, device_id: str, name: str, zone_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name, zone_data=zone_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="zone",
            operation=OperationType.UPDATE,
            resource_id=name,
            proposed_data=zone_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete zone")
    async def delete_zone(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="zone",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    # --- DHCP server -----------------------------------------------------------

    @service_operation("list DHCP servers")
    async def list_dhcp_servers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.list_dhcp_servers(vdom=vdom)
        return self._format_response(data, "dhcp_servers")

    @service_operation("create DHCP server")
    async def create_dhcp_server(
        self, device_id: str, server_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(server_data=server_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="dhcp_server",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=server_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update DHCP server")
    async def update_dhcp_server(
        self, device_id: str, server_id: str, server_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(server_id=server_id, server_data=server_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="dhcp_server",
            operation=OperationType.UPDATE,
            resource_id=server_id,
            proposed_data=server_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete DHCP server")
    async def delete_dhcp_server(
        self, device_id: str, server_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(server_id=server_id)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="dhcp_server",
            operation=OperationType.DELETE,
            resource_id=server_id,
            proposed_data=None,
        )
        return self._format_change_preview(preview)
