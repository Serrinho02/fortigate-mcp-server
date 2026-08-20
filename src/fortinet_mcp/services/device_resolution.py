"""
The bridge between this codebase's two device-identity systems.

Every Phase 2-7 service (Device/Policy/Network/Routing/Vip/Analysis/
Documentation/Intent/Vpn) and ChangeService historically resolved
`device_id` only against the legacy FortiGateManager (config.json-backed,
arbitrary string ids). Phase 1's inventory DB (Customer/Site/Device,
resolved dynamically by name/site/customer/IP through ConnectionManager)
was a second, separate device-identity system that only `connection.*`
and `fleet.*` tools ever consulted -- a device registered exclusively via
`inventory.register_device_pending` was invisible to every other tool
(get_device_status, list_interfaces, analysis.*, vpn.*, ...), failing with
a "not found" error that had nothing to do with the device's actual
reachability.

`resolve_adapter` closes that gap: try the legacy manager first (fast,
synchronous, no behavior change for existing config.json-based devices),
then fall back to the inventory DB via ConnectionManager if the id isn't
found there. A device now only needs to exist in *one* of the two systems
to be usable by every tool.
"""
from __future__ import annotations

from typing import Optional

from src.fortigate_mcp.core.fortigate import FortiGateManager

from ..adapters.base import FortinetProductAdapter
from ..adapters.fortios.adapter import FortiOSAdapter
from ..errors import (
    AmbiguousTargetError,
    CredentialNotProvisionedError,
    DeviceConnectionError,
    DeviceNotFoundError,
)
from ..infra.connection_manager import ConnectionManager


async def resolve_adapter(
    device_id: str,
    fortigate_manager: FortiGateManager,
    connection_manager: Optional[ConnectionManager],
) -> FortinetProductAdapter:
    """Resolve `device_id` to a live adapter.

    Raises:
        ValueError: not found in either system. If the inventory lookup
            found the device but hit a more specific problem (ambiguous
            target, credential not provisioned, health probe failed), that
            more actionable message is surfaced instead of a generic
            "not found".
    """
    try:
        client = fortigate_manager.get_device(device_id)
        return FortiOSAdapter(client)
    except ValueError:
        pass  # not in the legacy manager -- try the inventory below

    if connection_manager is not None:
        try:
            session = await connection_manager.connect(device_id)
            return session.adapter
        except DeviceNotFoundError:
            pass  # not in the inventory either -- fall through to the combined error
        except (AmbiguousTargetError, CredentialNotProvisionedError, DeviceConnectionError) as e:
            raise ValueError(str(e)) from e

    available = list(fortigate_manager.devices.keys())
    raise ValueError(
        f"Device '{device_id}' not found in legacy config or inventory. "
        f"Available legacy devices: {available}"
    )
