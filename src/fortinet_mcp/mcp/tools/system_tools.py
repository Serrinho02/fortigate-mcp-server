"""
system.* MCP tools -- device-level configuration: DNS, NTP, syslog, SNMP,
global settings (hostname/timezone/admin ports), local admin accounts, HA.
Dotted taxonomy names become underscore-joined Python tool names, matching
the other tool modules (system.get_dns -> system_get_dns).

Security note: create_admin/update_admin take `password` as a normal tool
argument -- visible in the conversation/tool-call history, the same
documented tradeoff as vpn_tools.py's psksecret (FortiGate never returns an
existing password on GET, so there's nothing to redact on the read path).

Operational note: system_update_global and system_update_ha_config can
disrupt the current management session or HA cluster membership -- this is
called out directly in their tool descriptions below since that's what
Claude reads before calling them.
"""
from __future__ import annotations

from typing import Annotated, Any, Dict, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...services.system_service import SystemService

_DeviceId = Annotated[str, Field(description="FortiGate device identifier")]
_Vdom = Annotated[Optional[str], Field(description="Virtual Domain", default=None)]


def register_system_tools(mcp: FastMCP, system_service: SystemService) -> None:
    # --- DNS -----------------------------------------------------------------

    @mcp.tool(description="Get DNS server settings for a device/VDOM.")
    async def system_get_dns(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.get_dns(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose updating DNS server settings (primary/secondary DNS, "
            "protocol). Returns a diff + change_id; call change.apply(change_id) "
            "to actually apply it."
        )
    )
    async def system_update_dns(
        device_id: _DeviceId,
        dns_data: Annotated[Dict[str, Any], Field(description="DNS fields, e.g. primary/secondary")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_dns(device_id, dns_data, vdom)

    # --- NTP -----------------------------------------------------------------

    @mcp.tool(description="Get NTP settings for a device.")
    async def system_get_ntp(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.get_ntp(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose updating NTP settings (ntpsync, NTP server list, sync "
            "interval). Returns a diff + change_id."
        )
    )
    async def system_update_ntp(
        device_id: _DeviceId,
        ntp_data: Annotated[Dict[str, Any], Field(description="NTP fields, e.g. ntpsync/server list")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_ntp(device_id, ntp_data, vdom)

    # --- Syslog ----------------------------------------------------------------

    @mcp.tool(description="Get syslogd (remote logging) settings for a device.")
    async def system_get_syslog(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.get_syslog(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose updating syslogd settings (remote syslog server, port, "
            "facility, format). Returns a diff + change_id."
        )
    )
    async def system_update_syslog(
        device_id: _DeviceId,
        syslog_data: Annotated[Dict[str, Any], Field(description="Syslog fields, e.g. status/server/port")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_syslog(device_id, syslog_data, vdom)

    # --- SNMP ------------------------------------------------------------------

    @mcp.tool(description="Get global SNMP agent settings (enable/description/contact/location).")
    async def system_get_snmp_sysinfo(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.get_snmp_sysinfo(device_id, vdom)

    @mcp.tool(description="Propose updating global SNMP agent settings. Returns a diff + change_id.")
    async def system_update_snmp_sysinfo(
        device_id: _DeviceId,
        sysinfo_data: Annotated[Dict[str, Any], Field(description="SNMP sysinfo fields, e.g. status/contact-info")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_snmp_sysinfo(device_id, sysinfo_data, vdom)

    @mcp.tool(description="List SNMP v1/v2c communities. SNMPv3 users are not yet supported by this server.")
    async def system_list_snmp_communities(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.list_snmp_communities(device_id, vdom)

    @mcp.tool(
        description="Propose creating an SNMP v1/v2c community (name, hosts allowed to query, queries enabled). Returns a diff + change_id."
    )
    async def system_create_snmp_community(
        device_id: _DeviceId,
        community_data: Annotated[Dict[str, Any], Field(description="Community fields, e.g. name/hosts/query-v2c-status")],
        vdom: _Vdom = None,
    ):
        return await system_service.create_snmp_community(device_id, community_data, vdom)

    @mcp.tool(description="Propose updating an SNMP v1/v2c community. Returns a diff + change_id.")
    async def system_update_snmp_community(
        device_id: _DeviceId,
        community_id: Annotated[str, Field(description="Community id")],
        community_data: Annotated[Dict[str, Any], Field(description="Community fields to update")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_snmp_community(device_id, community_id, community_data, vdom)

    @mcp.tool(description="Propose deleting an SNMP v1/v2c community. Returns a diff + change_id.")
    async def system_delete_snmp_community(
        device_id: _DeviceId,
        community_id: Annotated[str, Field(description="Community id")],
        vdom: _Vdom = None,
    ):
        return await system_service.delete_snmp_community(device_id, community_id, vdom)

    # --- System global settings -------------------------------------------------

    @mcp.tool(description="Get global system settings (hostname, timezone, admin/mgmt ports, vdom-mode, ...).")
    async def system_get_global(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.get_global_settings(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose updating global system settings (hostname, timezone, "
            "admin-sport/admin-ssh-port, vdom-mode, ...). WARNING: changing "
            "the admin ports or switching vdom-mode can disrupt the current "
            "management session/connection to this device -- review the diff "
            "carefully before calling change.apply. Returns a diff + change_id."
        )
    )
    async def system_update_global(
        device_id: _DeviceId,
        global_data: Annotated[Dict[str, Any], Field(description="Global system fields to update")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_global_settings(device_id, global_data, vdom)

    # --- Admin users -------------------------------------------------------------

    @mcp.tool(description="List local admin (management user) accounts.")
    async def system_list_admins(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.list_admins(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose creating a local admin account. Note: `password` is a "
            "normal argument here and will be visible in the conversation -- "
            "FortiGate never returns it on GET, so there's no read-side leak, "
            "but be mindful on write. Returns a diff + change_id."
        )
    )
    async def system_create_admin(
        device_id: _DeviceId,
        admin_data: Annotated[Dict[str, Any], Field(description="Admin fields, e.g. name/password/accprofile")],
        vdom: _Vdom = None,
    ):
        return await system_service.create_admin(device_id, admin_data, vdom)

    @mcp.tool(description="Propose updating a local admin account. Returns a diff + change_id.")
    async def system_update_admin(
        device_id: _DeviceId,
        username: Annotated[str, Field(description="Admin username")],
        admin_data: Annotated[Dict[str, Any], Field(description="Admin fields to update")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_admin(device_id, username, admin_data, vdom)

    @mcp.tool(description="Propose deleting a local admin account. Returns a diff + change_id.")
    async def system_delete_admin(
        device_id: _DeviceId,
        username: Annotated[str, Field(description="Admin username")],
        vdom: _Vdom = None,
    ):
        return await system_service.delete_admin(device_id, username, vdom)

    # --- HA configuration -------------------------------------------------------------

    @mcp.tool(description="Get high-availability (HA) cluster configuration.")
    async def system_get_ha_config(device_id: _DeviceId, vdom: _Vdom = None):
        return await system_service.get_ha_config(device_id, vdom)

    @mcp.tool(
        description=(
            "Propose updating HA cluster configuration (mode, group-id/"
            "group-name, password, priority, heartbeat/monitor interfaces, "
            "override). WARNING: misconfiguration can affect cluster "
            "membership and reachability -- review the diff carefully before "
            "calling change.apply. Returns a diff + change_id."
        )
    )
    async def system_update_ha_config(
        device_id: _DeviceId,
        ha_data: Annotated[Dict[str, Any], Field(description="HA fields to update")],
        vdom: _Vdom = None,
    ):
        return await system_service.update_ha_config(device_id, ha_data, vdom)
