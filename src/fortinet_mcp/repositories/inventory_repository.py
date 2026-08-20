"""
InventoryRepository -- CRUD over Customer/Site/Device/VDOM.

Every device that goes through `register_device_pending` gets a freshly
minted `credential_id` but no secret: provisioning the actual secret is a
separate, human-only step (see `infra/credential_manager.py` and
`cli/cred.py`). This repository never touches the OS keyring.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..errors import DuplicateNameError
from ..infra.models_orm import Customer, Device, Site, VDOM, new_id


class InventoryRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    # --- Customers ---------------------------------------------------------

    async def get_customer_by_name(self, name: str) -> Optional[Customer]:
        stmt = select(Customer).where(Customer.name == name)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_or_create_customer(self, name: str, tags: Optional[str] = None) -> Customer:
        customer = await self.get_customer_by_name(name)
        if customer is not None:
            return customer
        customer = Customer(name=name, tags=tags)
        self._session.add(customer)
        await self._session.flush()
        return customer

    async def list_customers(self) -> list[Customer]:
        stmt = select(Customer).order_by(Customer.name)
        return list((await self._session.execute(stmt)).scalars().all())

    # --- Sites ---------------------------------------------------------------

    async def get_site_by_name(self, customer_id: str, name: str) -> Optional[Site]:
        stmt = select(Site).where(Site.customer_id == customer_id, Site.name == name)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_or_create_site(
        self, customer_id: str, name: str, location: Optional[str] = None
    ) -> Site:
        site = await self.get_site_by_name(customer_id, name)
        if site is not None:
            return site
        site = Site(customer_id=customer_id, name=name, location=location)
        self._session.add(site)
        await self._session.flush()
        return site

    async def list_sites(self, customer_id: Optional[str] = None) -> list[Site]:
        stmt = select(Site).order_by(Site.name)
        if customer_id is not None:
            stmt = stmt.where(Site.customer_id == customer_id)
        return list((await self._session.execute(stmt)).scalars().all())

    # --- Devices ---------------------------------------------------------

    async def create_device(
        self,
        site_id: str,
        name: str,
        mgmt_host: str,
        *,
        mgmt_port: int = 443,
        product_type: str = "fortios",
        default_vdom: str = "root",
        verify_ssl: bool = True,
        timeout: int = 30,
        tags: Optional[str] = None,
    ) -> Device:
        existing = await self._session.execute(
            select(Device).where(Device.site_id == site_id, Device.name == name)
        )
        if existing.scalar_one_or_none() is not None:
            raise DuplicateNameError(f"Device '{name}' already exists in this site")

        device = Device(
            site_id=site_id,
            name=name,
            mgmt_host=mgmt_host,
            mgmt_port=mgmt_port,
            product_type=product_type,
            default_vdom=default_vdom,
            verify_ssl=verify_ssl,
            timeout=timeout,
            tags=tags,
            credential_id=new_id("cred"),
        )
        self._session.add(device)
        await self._session.flush()
        return device

    async def register_device_pending(
        self,
        customer_name: str,
        site_name: str,
        device_name: str,
        mgmt_host: str,
        *,
        mgmt_port: int = 443,
        product_type: str = "fortios",
        default_vdom: str = "root",
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> Device:
        """Create Customer/Site if missing, then the Device row.

        Only metadata is collected here -- the returned Device's
        `credential_id` has no secret behind it yet. The MCP tool built on
        top of this method must tell the human to run `cli/cred.py` next.
        """
        customer = await self.get_or_create_customer(customer_name)
        site = await self.get_or_create_site(customer.id, site_name)
        return await self.create_device(
            site.id,
            device_name,
            mgmt_host,
            mgmt_port=mgmt_port,
            product_type=product_type,
            default_vdom=default_vdom,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    async def get_device(self, device_id: str) -> Optional[Device]:
        stmt = (
            select(Device)
            .where(Device.id == device_id)
            .options(selectinload(Device.site).selectinload(Site.customer))
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_devices(
        self, customer_id: Optional[str] = None, site_id: Optional[str] = None
    ) -> list[Device]:
        stmt = select(Device).options(selectinload(Device.site).selectinload(Site.customer))
        if site_id is not None:
            stmt = stmt.where(Device.site_id == site_id)
        elif customer_id is not None:
            stmt = stmt.join(Site).where(Site.customer_id == customer_id)
        stmt = stmt.order_by(Device.name)
        return list((await self._session.execute(stmt)).scalars().all())

    async def remove_device(self, device_id: str) -> None:
        device = await self.get_device(device_id)
        if device is None:
            raise LookupError(f"Device '{device_id}' not found")
        await self._session.delete(device)
        await self._session.flush()

    # --- VDOMs ---------------------------------------------------------

    async def sync_vdoms(self, device_id: str, vdom_names: list[str], default_vdom: str) -> None:
        """Replace the device's known VDOM list with `vdom_names`."""
        existing = (
            await self._session.execute(select(VDOM).where(VDOM.device_id == device_id))
        ).scalars().all()
        for vdom in existing:
            await self._session.delete(vdom)
        await self._session.flush()

        for vdom_name in vdom_names:
            self._session.add(
                VDOM(device_id=device_id, name=vdom_name, is_default=(vdom_name == default_vdom))
            )
        await self._session.flush()
