"""
inventory.* MCP tools -- Customer/Site/Device CRUD against the new
SQLAlchemy-backed inventory store. Additive alongside the legacy
add_device/list_devices tools in fortigate_mcp; nothing here ever touches
a secret. `inventory_register_device_pending` only ever collects metadata
and returns a fresh credential_id that a human must provision separately
via `fortinet-mcp-cred` -- see infra/credential_manager.py and cli/cred.py.
"""
from __future__ import annotations

from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...errors import DuplicateNameError
from ...infra.credential_manager import CredentialManager
from ...repositories.inventory_repository import InventoryRepository


def register_inventory_tools(
    mcp: FastMCP,
    session_factory: async_sessionmaker[AsyncSession],
    credential_manager: CredentialManager,
) -> None:
    @mcp.tool(description="List all customers (tenants) in the inventory.")
    async def inventory_list_customers():
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            customers = await inventory.list_customers()
            return [{"id": c.id, "name": c.name} for c in customers]

    @mcp.tool(description="List sites, optionally filtered by customer name.")
    async def inventory_list_sites(
        customer_name: Annotated[
            Optional[str], Field(description="Filter to this customer's sites", default=None)
        ] = None,
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            customer_id = None
            if customer_name is not None:
                customer = await inventory.get_customer_by_name(customer_name)
                if customer is None:
                    return {"error": f"Customer '{customer_name}' not found"}
                customer_id = customer.id
            sites = await inventory.list_sites(customer_id)
            return [
                {"id": s.id, "name": s.name, "customer_id": s.customer_id, "location": s.location}
                for s in sites
            ]

    @mcp.tool(
        description="List devices in the inventory, optionally filtered by customer name."
    )
    async def inventory_list_devices(
        customer_name: Annotated[
            Optional[str], Field(description="Filter to this customer's devices", default=None)
        ] = None,
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            customer_id = None
            if customer_name is not None:
                customer = await inventory.get_customer_by_name(customer_name)
                if customer is None:
                    return {"error": f"Customer '{customer_name}' not found"}
                customer_id = customer.id
            devices = await inventory.list_devices(customer_id=customer_id)
            return [
                {
                    "id": d.id,
                    "name": d.name,
                    "customer": d.site.customer.name,
                    "site": d.site.name,
                    "mgmt_host": d.mgmt_host,
                    "product_type": d.product_type,
                    "default_vdom": d.default_vdom,
                    "credential_provisioned": (
                        credential_manager.is_provisioned(d.credential_id)
                        if d.credential_id
                        else False
                    ),
                }
                for d in devices
            ]

    @mcp.tool(
        description=(
            "Register a new device in the inventory (metadata only: host, name, "
            "customer, site). This does NOT provision credentials -- the returned "
            "credential_id must be provisioned by a human running "
            "`fortinet-mcp-cred set <credential_id>` locally. Never pass a password "
            "or API token to this tool."
        )
    )
    async def inventory_register_device_pending(
        customer_name: Annotated[
            str, Field(description="Customer/tenant name (created if it doesn't exist)")
        ],
        site_name: Annotated[
            str, Field(description="Site name within the customer (created if it doesn't exist)")
        ],
        device_name: Annotated[str, Field(description="Unique device name within the site")],
        mgmt_host: Annotated[str, Field(description="Management IP address or hostname")],
        mgmt_port: Annotated[int, Field(description="HTTPS management port", default=443)] = 443,
        default_vdom: Annotated[str, Field(description="Default VDOM name", default="root")] = "root",
        verify_ssl: Annotated[bool, Field(description="Verify TLS certificate", default=True)] = True,
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            try:
                device = await inventory.register_device_pending(
                    customer_name,
                    site_name,
                    device_name,
                    mgmt_host,
                    mgmt_port=mgmt_port,
                    default_vdom=default_vdom,
                    verify_ssl=verify_ssl,
                )
            except DuplicateNameError as e:
                return {"error": str(e)}
            await session.commit()
            return {
                "device_id": device.id,
                "credential_id": device.credential_id,
                "next_step": (
                    f"Run locally (not through Claude): "
                    f"fortinet-mcp-cred set {device.credential_id} --auth-type token "
                    "(or --auth-type basic)"
                ),
            }

    @mcp.tool(
        description=(
            "Remove a device from the inventory and delete its stored credential "
            "from the OS keyring."
        )
    )
    async def inventory_remove_device(
        device_id: Annotated[str, Field(description="Device id to remove")],
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            device = await inventory.get_device(device_id)
            if device is None:
                return {"error": f"Device '{device_id}' not found"}
            credential_id = device.credential_id
            await inventory.remove_device(device_id)
            await session.commit()
        if credential_id is not None:
            credential_manager.delete(credential_id)
        return {"removed": device_id}
