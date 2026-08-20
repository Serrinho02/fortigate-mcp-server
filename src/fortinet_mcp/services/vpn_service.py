"""
VpnService -- IPsec VPN tunnel management (phase1 = tunnel/gateway, phase2
= traffic selector) plus read-only IPsec/SSL VPN status visibility.

Mutating methods (create/update/delete of phase1/phase2) route through
ChangeService exactly like PolicyService -- they return a preview +
change_id instead of executing immediately, gated by the same
READ_ONLY/SAFE/FULL mode enforcement as every other resource.

Scope note: SSL VPN portal/settings *mutation* is intentionally not
included here -- only read-only visibility (settings + active sessions).
Site-to-site IPsec is the common "make VPN work" case; SSL VPN portal
configuration (user groups, web portal customization, authentication) is
a materially larger feature that can be added later if needed.

Security note: unlike FortiGate device credentials (which never reach
Claude -- see infra/credential_manager.py), an IPsec tunnel's pre-shared
key (`psksecret`) is passed as a normal tool argument here, the same way
policy_data/vip_data are for every other resource. It will be visible in
the conversation/tool-call history. FortiGate itself never returns
psksecret in GET responses (it's write-only), so this is a real,
documented tradeoff, not an oversight.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from . import change_dispatch
from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class VpnService(FortiGateServiceBase):
    # --- IPsec phase1 (tunnel/gateway) ---------------------------------------

    @service_operation("list IPsec tunnels")
    async def list_ipsec_tunnels(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        tunnels = await adapter.list_ipsec_phase1(vdom=vdom)
        return self._format_response(tunnels, "ipsec_tunnels")

    @service_operation("get IPsec tunnel detail")
    async def get_ipsec_tunnel_detail(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)
        adapter = await self._get_adapter(device_id)
        tunnel = await adapter.get_ipsec_phase1(name, vdom=vdom)
        return self._format_response(tunnel, "ipsec_tunnel_detail")

    @service_operation("create IPsec tunnel")
    async def create_ipsec_tunnel(
        self, device_id: str, tunnel_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(tunnel_data=tunnel_data)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ipsec_phase1",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=tunnel_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update IPsec tunnel")
    async def update_ipsec_tunnel(
        self, device_id: str, name: str, tunnel_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name, tunnel_data=tunnel_data)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ipsec_phase1",
            operation=OperationType.UPDATE,
            resource_id=name,
            proposed_data=tunnel_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete IPsec tunnel")
    async def delete_ipsec_tunnel(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ipsec_phase1",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    # --- IPsec phase2 (traffic selector) ---------------------------------------

    @service_operation("list IPsec phase2 selectors")
    async def list_ipsec_phase2(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        selectors = await adapter.list_ipsec_phase2(vdom=vdom)
        return self._format_response(selectors, "ipsec_phase2_selectors")

    @service_operation("create IPsec phase2 selector")
    async def create_ipsec_phase2(
        self, device_id: str, phase2_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(phase2_data=phase2_data)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ipsec_phase2",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=phase2_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update IPsec phase2 selector")
    async def update_ipsec_phase2(
        self, device_id: str, name: str, phase2_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name, phase2_data=phase2_data)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ipsec_phase2",
            operation=OperationType.UPDATE,
            resource_id=name,
            proposed_data=phase2_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete IPsec phase2 selector")
    async def delete_ipsec_phase2(
        self, device_id: str, name: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(name=name)

        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ipsec_phase2",
            operation=OperationType.DELETE,
            resource_id=name,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    # --- Read-only status / SSL VPN visibility ---------------------------------------

    @service_operation("get IPsec tunnel status")
    async def get_ipsec_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        status = await adapter.get_ipsec_tunnel_status(vdom=vdom)
        return self._format_response(status, "ipsec_tunnel_status")

    @service_operation("get SSL VPN settings")
    async def get_ssl_vpn_settings(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        settings = await adapter.get_ssl_vpn_settings(vdom=vdom)
        return self._format_response(settings, "ssl_vpn_settings")

    @service_operation("list SSL VPN sessions")
    async def list_ssl_vpn_sessions(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        sessions = await adapter.get_ssl_vpn_sessions(vdom=vdom)
        return self._format_response(sessions, "ssl_vpn_sessions")
