"""
Maps `resource_type` to the FortiOSAdapter method names for get/create/
update/delete, so ChangeService can preview/apply/rollback any gated
mutation generically -- without each Service class handing ChangeService
its own bespoke adapter calls, and without ChangeService needing to know
FortiOS-specific method names directly.
"""
from __future__ import annotations

from typing import Any, Optional

from ..adapters.base import FortinetProductAdapter

_RESOURCE_OPS: dict[str, dict[str, str]] = {
    "firewall_policy": {
        "list": "list_policies",
        "get": "get_policy",
        "create": "create_policy",
        "update": "update_policy",
        "delete": "delete_policy",
    },
    "address_object": {
        "list": "list_address_objects",
        "create": "create_address_object",
        "update": "update_address_object",
        "delete": "delete_address_object",
    },
    "service_object": {
        "list": "list_service_objects",
        "create": "create_service_object",
        "update": "update_service_object",
        "delete": "delete_service_object",
    },
    "static_route": {
        "list": "list_static_routes",
        "get": "get_static_route",
        "create": "create_static_route",
        "update": "update_static_route",
        "delete": "delete_static_route",
    },
    "virtual_ip": {
        "list": "list_virtual_ips",
        "get": "get_virtual_ip",
        "create": "create_virtual_ip",
        "update": "update_virtual_ip",
        "delete": "delete_virtual_ip",
    },
    "ipsec_phase1": {
        "list": "list_ipsec_phase1",
        "get": "get_ipsec_phase1",
        "create": "create_ipsec_phase1",
        "update": "update_ipsec_phase1",
        "delete": "delete_ipsec_phase1",
    },
    "ipsec_phase2": {
        "list": "list_ipsec_phase2",
        "get": "get_ipsec_phase2",
        "create": "create_ipsec_phase2",
        "update": "update_ipsec_phase2",
        "delete": "delete_ipsec_phase2",
    },
    # --- Singleton system settings (see _SINGLETON_RESOURCE_TYPES below) ----
    "dns": {"get": "get_dns_settings", "update": "update_dns_settings"},
    "ntp": {"get": "get_ntp_settings", "update": "update_ntp_settings"},
    "syslog": {"get": "get_syslog_settings", "update": "update_syslog_settings"},
    "snmp_sysinfo": {"get": "get_snmp_sysinfo", "update": "update_snmp_sysinfo"},
    "system_global": {"get": "get_system_global", "update": "update_system_global"},
    "ha": {"get": "get_ha_config", "update": "update_ha_config"},
    # --- Keyed system settings ------------------------------------------------
    "snmp_community": {
        "list": "list_snmp_communities",
        "get": "get_snmp_community",
        "create": "create_snmp_community",
        "update": "update_snmp_community",
        "delete": "delete_snmp_community",
    },
    "admin": {
        "list": "list_admins",
        "get": "get_admin",
        "create": "create_admin",
        "update": "update_admin",
        "delete": "delete_admin",
    },
    # --- VDOM lifecycle (keyed by name, no "update" -- a VDOM is recreated,
    # not updated, through this table). No "list" either: `list_vdoms()` takes
    # no vdom kwarg at all (see adapters/base.py), unlike every other listed
    # resource type here -- DeviceService.discover_vdoms calls it directly
    # instead of through this generic table. ------------------------------------
    "vdom": {
        "create": "create_vdom",
        "delete": "delete_vdom",
    },
    "vdom_link": {
        "list": "list_vdom_links",
        "get": "get_vdom_link",
        "create": "create_vdom_link",
        "delete": "delete_vdom_link",
    },
    # --- Interfaces, zones, DHCP server (Phase C) -------------------------------
    "interface": {
        "list": "list_interfaces",
        "get": "get_interface",
        "create": "create_interface",
        "update": "update_interface",
        "delete": "delete_interface",
    },
    "zone": {
        "list": "list_zones",
        "get": "get_zone",
        "create": "create_zone",
        "update": "update_zone",
        "delete": "delete_zone",
    },
    "dhcp_server": {
        "list": "list_dhcp_servers",
        "get": "get_dhcp_server",
        "create": "create_dhcp_server",
        "update": "update_dhcp_server",
        "delete": "delete_dhcp_server",
    },
}

_SINGLETON_RESOURCE_TYPES: frozenset[str] = frozenset(
    {"dns", "ntp", "syslog", "snmp_sysinfo", "system_global", "ha"}
)
"""Resource types with exactly one instance per device/VDOM -- no id, only
get+update (never create/delete, so `_RESOURCE_OPS` for these has no
"create"/"delete" key -- attempting either already fails naturally with the
"does not support operation" error in `execute`). `fetch_current`/`execute`
special-case these: a singleton's `resource_id` is always None by
definition, which would otherwise look identical to "this is a CREATE,
nothing to diff yet" for a keyed resource -- so the None-id-means-skip
shortcut below only applies to non-singleton types."""


def known_resource_types() -> list[str]:
    return sorted(_RESOURCE_OPS)


def _ops_for(resource_type: str) -> dict[str, str]:
    ops = _RESOURCE_OPS.get(resource_type)
    if ops is None:
        raise ValueError(
            f"Unknown resource_type '{resource_type}'. Known: {known_resource_types()}"
        )
    return ops


def unwrap_single(response: Any) -> Optional[dict[str, Any]]:
    """FortiOS GET responses are typically `{"results": {...}}` (or a
    single-element list for some endpoints); normalize to the inner dict so
    it compares like-for-like with the plain-dict `proposed_data` callers
    pass in. Also the shared single-item unwrap for any other service that
    needs it (e.g. get_status) -- when there's no "results" key at all, the
    response itself is returned as-is."""
    if isinstance(response, dict) and "results" in response:
        results = response["results"]
        if isinstance(results, list):
            return results[0] if results else None
        return results
    return response


async def fetch_current(
    adapter: FortinetProductAdapter,
    resource_type: str,
    resource_id: Optional[str],
    vdom: Optional[str],
) -> Optional[dict[str, Any]]:
    """Best-effort GET of the current resource state, for diffing/drift
    checks. Returns None when there's nothing to fetch (no resource_id yet
    -- a CREATE -- for a keyed resource type), the resource type has no
    single-item getter, or the GET itself fails (a legitimate state to diff
    against for a CREATE).

    Singleton resource types (see `_SINGLETON_RESOURCE_TYPES`) have no id at
    all -- their `resource_id` is always None, which is not "nothing to
    diff" the way it is for a keyed type; the current state is always
    fetched for them."""
    ops = _ops_for(resource_type)
    getter = ops.get("get")
    if getter is None:
        return None
    is_singleton = resource_type in _SINGLETON_RESOURCE_TYPES
    if not is_singleton and resource_id is None:
        return None
    method = getattr(adapter, getter)
    try:
        response = await (method(vdom=vdom) if is_singleton else method(resource_id, vdom=vdom))
    except Exception:
        return None
    return unwrap_single(response)


async def execute(
    adapter: FortinetProductAdapter,
    resource_type: str,
    operation: str,
    resource_id: Optional[str],
    data: Optional[dict[str, Any]],
    vdom: Optional[str],
) -> Any:
    ops = _ops_for(resource_type)
    method_name = ops.get(operation)
    if method_name is None:
        raise ValueError(f"resource_type '{resource_type}' does not support operation '{operation}'")
    method = getattr(adapter, method_name)

    if operation == "update" and resource_type in _SINGLETON_RESOURCE_TYPES:
        return await method(data, vdom=vdom)
    if operation == "create":
        return await method(data, vdom=vdom)
    if operation == "update":
        return await method(resource_id, data, vdom=vdom)
    if operation == "delete":
        return await method(resource_id, vdom=vdom)
    raise ValueError(f"Unknown operation '{operation}'")


def unwrap_list(response: Any) -> list[dict[str, Any]]:
    """FortiOS list endpoints return `{"results": [...]}`. Shared by
    list_all below and by any service that lists a resource directly
    through the adapter without going through this dispatch table."""
    if isinstance(response, dict):
        results = response.get("results", [])
        if isinstance(results, list):
            return results
        return [results] if results else []
    return list(response) if response else []


async def list_all(
    adapter: FortinetProductAdapter, resource_type: str, vdom: Optional[str]
) -> list[dict[str, Any]]:
    """Fetch every instance of `resource_type` on `adapter`. Used by fleet
    operations (Phase 6), which need whole-list comparisons across devices
    rather than a single resource by id."""
    ops = _ops_for(resource_type)
    method_name = ops.get("list")
    if method_name is None:
        raise ValueError(f"resource_type '{resource_type}' does not support 'list'")
    method = getattr(adapter, method_name)
    response = await method(vdom=vdom)
    return unwrap_list(response)


def extract_created_resource_id(response: Any) -> Optional[str]:
    """Best-effort extraction of the id FortiOS assigned a newly created
    resource, from the raw create response (`mkey` on a real FortiGate).
    Returns None if absent -- rollback of that specific CREATE then can't
    auto-delete, and reports exactly that instead of guessing."""
    if not isinstance(response, dict):
        return None
    mkey = response.get("mkey")
    return str(mkey) if mkey is not None else None
