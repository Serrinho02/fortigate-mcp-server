"""
SystemService -- device-level "system configuration" domain: DNS, NTP,
syslog, SNMP, global settings (hostname/timezone/admin ports), local admin
accounts, and HA. This is the missing piece for taking a factory-default
FortiGate to a fully configured end state (see VdomService/RoutingService
for VDOM lifecycle and interface/zone/DHCP, added in later phases of the
same effort).

Every mutation here routes through ChangeService exactly like PolicyService/
VpnService -- preview returns a diff + change_id, change.apply(change_id)
executes it, gated by the same READ_ONLY/SAFE/FULL mode enforcement as
every other resource. Nothing here gets a shortcut.

Singleton resources (dns/ntp/syslog/snmp_sysinfo/system_global/ha) have no
id -- there is exactly one instance per device (or per VDOM for dns/syslog).
Their update preview is called with resource_id=None; change_dispatch.py's
_SINGLETON_RESOURCE_TYPES set is what makes ChangeService still fetch
current state for diffing despite that None id (see that module's
docstring for why a None id doesn't mean "nothing to diff" here the way it
does for a keyed CREATE).

Security/operational notes (documented tradeoffs, not oversights):
- create_admin/update_admin take `password` as a normal tool argument, the
  same way vpn_service.py's psksecret is handled: visible to Claude in the
  conversation/tool-call history, because FortiOS itself never returns
  existing passwords in GET responses (write-only) -- there's no way to
  hide it that wouldn't also break the preview/diff the change engine
  needs to show before applying.
- update_global_settings and update_ha_config can disrupt the current
  management session (hostname/admin-port changes can drop existing admin
  connections; HA config changes affect cluster membership/reachability).
  This is flagged in the MCP tool descriptions (server.py/server_http.py),
  not just here, since that's what Claude actually reads before calling.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateServiceBase, service_operation
from .mode_policy import OperationType


class SystemService(FortiGateServiceBase):
    # --- DNS -------------------------------------------------------------------

    @service_operation("get DNS settings")
    async def get_dns(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.get_dns_settings(vdom=vdom)
        return self._format_response(data, "dns_settings")

    @service_operation("update DNS settings")
    async def update_dns(
        self, device_id: str, dns_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(dns_data=dns_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="dns",
            operation=OperationType.UPDATE,
            resource_id=None,
            proposed_data=dns_data,
        )
        return self._format_change_preview(preview)

    # --- NTP -------------------------------------------------------------------

    @service_operation("get NTP settings")
    async def get_ntp(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.get_ntp_settings(vdom=vdom)
        return self._format_response(data, "ntp_settings")

    @service_operation("update NTP settings")
    async def update_ntp(
        self, device_id: str, ntp_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(ntp_data=ntp_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ntp",
            operation=OperationType.UPDATE,
            resource_id=None,
            proposed_data=ntp_data,
        )
        return self._format_change_preview(preview)

    # --- Syslog ------------------------------------------------------------------

    @service_operation("get syslog settings")
    async def get_syslog(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.get_syslog_settings(vdom=vdom)
        return self._format_response(data, "syslog_settings")

    @service_operation("update syslog settings")
    async def update_syslog(
        self, device_id: str, syslog_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(syslog_data=syslog_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="syslog",
            operation=OperationType.UPDATE,
            resource_id=None,
            proposed_data=syslog_data,
        )
        return self._format_change_preview(preview)

    # --- SNMP --------------------------------------------------------------------

    @service_operation("get SNMP sysinfo")
    async def get_snmp_sysinfo(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.get_snmp_sysinfo(vdom=vdom)
        return self._format_response(data, "snmp_sysinfo")

    @service_operation("update SNMP sysinfo")
    async def update_snmp_sysinfo(
        self, device_id: str, sysinfo_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(sysinfo_data=sysinfo_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="snmp_sysinfo",
            operation=OperationType.UPDATE,
            resource_id=None,
            proposed_data=sysinfo_data,
        )
        return self._format_change_preview(preview)

    @service_operation("list SNMP communities")
    async def list_snmp_communities(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.list_snmp_communities(vdom=vdom)
        return self._format_response(data, "snmp_communities")

    @service_operation("create SNMP community")
    async def create_snmp_community(
        self, device_id: str, community_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(community_data=community_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="snmp_community",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=community_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update SNMP community")
    async def update_snmp_community(
        self,
        device_id: str,
        community_id: str,
        community_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        self._validate_required_params(community_id=community_id, community_data=community_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="snmp_community",
            operation=OperationType.UPDATE,
            resource_id=community_id,
            proposed_data=community_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete SNMP community")
    async def delete_snmp_community(
        self, device_id: str, community_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(community_id=community_id)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="snmp_community",
            operation=OperationType.DELETE,
            resource_id=community_id,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    # --- System global settings ---------------------------------------------------

    @service_operation("get system global settings")
    async def get_global_settings(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.get_system_global(vdom=vdom)
        return self._format_response(data, "system_global")

    @service_operation("update system global settings")
    async def update_global_settings(
        self, device_id: str, global_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(global_data=global_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="system_global",
            operation=OperationType.UPDATE,
            resource_id=None,
            proposed_data=global_data,
        )
        return self._format_change_preview(preview)

    # --- Admin users ---------------------------------------------------------------

    @service_operation("list admin accounts")
    async def list_admins(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.list_admins(vdom=vdom)
        return self._format_response(data, "admins")

    @service_operation("create admin account")
    async def create_admin(
        self, device_id: str, admin_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(admin_data=admin_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="admin",
            operation=OperationType.CREATE,
            resource_id=None,
            proposed_data=admin_data,
        )
        return self._format_change_preview(preview)

    @service_operation("update admin account")
    async def update_admin(
        self, device_id: str, username: str, admin_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(username=username, admin_data=admin_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="admin",
            operation=OperationType.UPDATE,
            resource_id=username,
            proposed_data=admin_data,
        )
        return self._format_change_preview(preview)

    @service_operation("delete admin account")
    async def delete_admin(
        self, device_id: str, username: str, vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(username=username)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="admin",
            operation=OperationType.DELETE,
            resource_id=username,
            proposed_data=None,
        )
        return self._format_change_preview(preview)

    # --- HA configuration -------------------------------------------------------------

    @service_operation("get HA configuration")
    async def get_ha_config(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        adapter = await self._get_adapter(device_id)
        data = await adapter.get_ha_config(vdom=vdom)
        return self._format_response(data, "ha_config")

    @service_operation("update HA configuration")
    async def update_ha_config(
        self, device_id: str, ha_data: Dict[str, Any], vdom: Optional[str] = None
    ) -> List[Content]:
        self._validate_required_params(ha_data=ha_data)
        preview = await self.change_service.preview(
            device_id=device_id,
            vdom=vdom,
            resource_type="ha",
            operation=OperationType.UPDATE,
            resource_id=None,
            proposed_data=ha_data,
        )
        return self._format_change_preview(preview)
