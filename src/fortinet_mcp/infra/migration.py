"""
One-time helper: import devices from the legacy config/config.json into
the new inventory DB + OS keyring.

Run as a local script only -- never exposed as an MCP tool. It reads
plaintext secrets directly from the legacy config file (the same way the
old FortiGateManager always did) and writes them straight into the OS
keyring; no LLM or MCP tool call ever sees these values.

Usage:
    python -m src.fortinet_mcp.infra.migration --config config/config.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from ..infra.credential_manager import CredentialManager
from ..infra.db import create_engine, create_session_factory, init_models
from ..repositories.inventory_repository import InventoryRepository

DEFAULT_CUSTOMER = "Legacy"
DEFAULT_SITE = "Default"


async def migrate_config(
    config_path: Path,
    *,
    customer_name: str = DEFAULT_CUSTOMER,
    site_name: str = DEFAULT_SITE,
    database_url: Optional[str] = None,
) -> list[str]:
    """Import every device in the legacy config.json into the inventory DB
    and OS keyring. Returns the device_ids of newly created devices.

    Idempotent on device identity: devices are matched by (site, name) --
    re-running against an already-migrated device does not duplicate it,
    but its secret IS re-written to the keyring in case it changed.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    devices_cfg = raw.get("fortigate", {}).get("devices", {})
    if not devices_cfg:
        return []

    engine = create_engine(database_url)
    await init_models(engine)
    session_factory = create_session_factory(engine)
    credential_manager = CredentialManager()
    created_ids: list[str] = []

    async with session_factory() as session:
        inventory = InventoryRepository(session)
        customer = await inventory.get_or_create_customer(customer_name)
        site = await inventory.get_or_create_site(customer.id, site_name)
        existing_devices = {d.name: d for d in await inventory.list_devices(site_id=site.id)}

        for legacy_id, device_cfg in devices_cfg.items():
            device = existing_devices.get(legacy_id)
            if device is None:
                device = await inventory.create_device(
                    site.id,
                    legacy_id,
                    device_cfg["host"],
                    mgmt_port=device_cfg.get("port", 443),
                    default_vdom=device_cfg.get("vdom", "root"),
                    verify_ssl=device_cfg.get("verify_ssl", True),
                    timeout=device_cfg.get("timeout", 30),
                )
                created_ids.append(device.id)

            api_token = device_cfg.get("api_token")
            username = device_cfg.get("username")
            password = device_cfg.get("password")
            if api_token:
                credential_manager.set_secret(
                    device.credential_id, auth_type="token", api_token=api_token
                )
            elif username and password:
                credential_manager.set_secret(
                    device.credential_id, auth_type="basic", username=username, password=password
                )
            # else: leave unprovisioned -- connection.connect will raise
            # CredentialNotProvisionedError until a human runs cli/cred.py.

        await session.commit()

    await engine.dispose()
    return created_ids


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortinet-mcp-migrate",
        description=(
            "One-time import of the legacy config/config.json devices into "
            "the inventory DB + OS keyring."
        ),
    )
    parser.add_argument("--config", type=Path, default=Path("config/config.json"))
    parser.add_argument("--customer", default=DEFAULT_CUSTOMER)
    parser.add_argument("--site", default=DEFAULT_SITE)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.config.exists():
        print(f"error: config file not found: {args.config}", file=sys.stderr)
        return 1

    created = asyncio.run(
        migrate_config(args.config, customer_name=args.customer, site_name=args.site)
    )
    print(
        f"Migrated {len(created)} new device(s) into "
        f"customer='{args.customer}' site='{args.site}'."
    )
    print("Secrets were written directly to the OS credential store -- verify with:")
    print("  python -m src.fortinet_mcp.cli.cred status <credential_id>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
