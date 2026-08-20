"""
DeviceResolver -- turns a free-form target string ("Milano", "customer
Alfa", "10.10.10.1", an explicit device_id) into one or more `Device` rows.

Pure and network-free: it only ever queries the `InventoryRepository`.
Resolution never guesses silently -- an ambiguous match raises
`AmbiguousTargetError` with the candidate names so the caller (eventually
the Service layer) can hand the choice back to Claude instead of picking
one arbitrarily.

v1 scope: exact match, then prefix match, case-insensitive, in the order
device name -> site name -> customer name. No fuzzy/typo matching yet
(see architecture plan, Open Questions).
"""
from __future__ import annotations

from ..errors import AmbiguousTargetError, DeviceNotFoundError
from ..infra.models_orm import Device
from ..repositories.inventory_repository import InventoryRepository


class DeviceResolver:
    def __init__(self, inventory: InventoryRepository):
        self._inventory = inventory

    async def resolve(self, target: str) -> list[Device]:
        """Resolve `target` to one or more devices.

        Raises:
            ValueError: if `target` is empty.
            AmbiguousTargetError: if multiple devices match at the same
                resolution stage (exact device name, or prefix device name).
            DeviceNotFoundError: if nothing matches at all.
        """
        target_norm = target.strip()
        if not target_norm:
            raise ValueError("target must not be empty")
        lowered = target_norm.lower()

        devices = await self._inventory.list_devices()

        # 1. literal management-host match
        host_matches = [d for d in devices if d.mgmt_host.lower() == lowered]
        if host_matches:
            return host_matches

        # 2. explicit device_id match
        id_matches = [d for d in devices if d.id == target_norm]
        if id_matches:
            return id_matches

        # 3. exact device name
        exact_device = [d for d in devices if d.name.lower() == lowered]
        if len(exact_device) == 1:
            return exact_device
        if len(exact_device) > 1:
            raise AmbiguousTargetError(target_norm, sorted({d.name for d in exact_device}))

        # 4. exact site name -> all devices in that site
        exact_site = [d for d in devices if d.site.name.lower() == lowered]
        if exact_site:
            return exact_site

        # 5. exact customer name -> all devices under that customer
        exact_customer = [d for d in devices if d.site.customer.name.lower() == lowered]
        if exact_customer:
            return exact_customer

        # 6. prefix cascade: device name -> site name -> customer name
        prefix_device = [d for d in devices if d.name.lower().startswith(lowered)]
        if len(prefix_device) == 1:
            return prefix_device
        if len(prefix_device) > 1:
            raise AmbiguousTargetError(target_norm, sorted({d.name for d in prefix_device}))

        prefix_site = [d for d in devices if d.site.name.lower().startswith(lowered)]
        if prefix_site:
            return prefix_site

        prefix_customer = [d for d in devices if d.site.customer.name.lower().startswith(lowered)]
        if prefix_customer:
            return prefix_customer

        raise DeviceNotFoundError(target_norm)

    async def resolve_one(self, target: str) -> Device:
        """Like `resolve`, but requires exactly one match.

        Raises:
            AmbiguousTargetError: if `target` resolves to more than one device.
        """
        matches = await self.resolve(target)
        if len(matches) > 1:
            raise AmbiguousTargetError(target, sorted({d.name for d in matches}))
        return matches[0]
