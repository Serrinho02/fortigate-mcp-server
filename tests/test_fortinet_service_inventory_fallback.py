"""
End-to-end (at the Service layer) regression test for the exact bug
reported in production use: a device registered only via
`inventory.register_device_pending` (never added to the legacy
FortiGateManager/config.json) made get_device_status/list_interfaces/etc.
fail with "Resource not found", even though connection.connect worked fine
against the same device. Fixed by routing FortiGateServiceBase._get_adapter
through resolve_adapter() (services/device_resolution.py).

test_fortinet_device_resolution.py already covers resolve_adapter in
isolation; this file proves the wiring through real Service classes used
by the actual MCP tools (DeviceService.get_device_status,
RoutingService.list_interfaces).
"""
from typing import Any, Optional

import keyring
import pytest
import pytest_asyncio

from src.fortinet_mcp.adapters.base import Capability
from src.fortinet_mcp.adapters.registry import AdapterRegistry
from src.fortinet_mcp.infra.connection_manager import ConnectionManager
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.repositories.inventory_repository import InventoryRepository
from src.fortinet_mcp.services.device_service import DeviceService
from src.fortinet_mcp.services.routing_service import RoutingService
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class FakeInventoryAdapter:
    """Stands in for FortiOSAdapter -- just enough of the Protocol for
    get_device_status/list_interfaces to succeed end-to-end."""

    product_type = "fortios"

    def capabilities(self) -> frozenset[Capability]:
        return frozenset({Capability.SYSTEM_STATUS, Capability.INTERFACE})

    async def test_connection(self) -> bool:
        return True

    async def close(self) -> None:
        pass

    async def get_status(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return {
            "results": {"hostname": "CDM-OBM-HUB-FW01", "model_name": "FortiGate"},
            "version": "v7.4.0",
            "serial": "FGT-TEST-001",
        }

    async def list_interfaces(self, vdom: Optional[str] = None) -> dict[str, Any]:
        return {"results": [{"name": "port1", "status": "up"}]}


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'inventory.db').as_posix()}"
    engine = create_engine(db_url)
    await init_models(engine)
    factory = create_session_factory(engine)
    yield factory
    await engine.dispose()


@pytest.fixture
def credentials():
    return CredentialManager()


@pytest.fixture
def registry():
    reg = AdapterRegistry()
    reg.register("fortios", lambda client: FakeInventoryAdapter())
    return reg


@pytest.fixture
def connection_manager(session_factory, credentials, registry):
    return ConnectionManager(session_factory, credentials, registry)


@pytest_asyncio.fixture
async def inventory_only_device_id(session_factory, credentials):
    """A device that exists ONLY in the inventory DB -- fortigate_manager
    (config.json) knows nothing about it, mirroring the real bug report."""
    async with session_factory() as session:
        inventory = InventoryRepository(session)
        device = await inventory.register_device_pending(
            "CDM", "OBM-HUB", "CDM-OBM-HUB-FW01", "10.89.255.1"
        )
        await session.commit()
        device_id, credential_id = device.id, device.credential_id
    credentials.set_secret(credential_id, auth_type="token", api_token="s3cr3t")
    return device_id


class TestDeviceServiceInventoryFallback:
    @pytest.mark.asyncio
    async def test_get_device_status_succeeds_for_inventory_only_device(
        self, fortigate_manager, connection_manager, inventory_only_device_id
    ):
        service = DeviceService(fortigate_manager, connection_manager=connection_manager)

        result = await service.get_device_status(inventory_only_device_id)
        text = result[0].text

        assert "error" not in text.lower(), f"expected success, got: {text}"
        assert "CDM-OBM-HUB-FW01" in text

    @pytest.mark.asyncio
    async def test_get_device_status_still_fails_clearly_when_device_unknown_everywhere(
        self, fortigate_manager, connection_manager
    ):
        service = DeviceService(fortigate_manager, connection_manager=connection_manager)

        result = await service.get_device_status("totally-unknown-device")
        text = result[0].text

        assert "not found" in text.lower()


class TestRoutingServiceInventoryFallback:
    @pytest.mark.asyncio
    async def test_list_interfaces_succeeds_for_inventory_only_device(
        self, fortigate_manager, connection_manager, inventory_only_device_id
    ):
        service = RoutingService(fortigate_manager, change_service=None, connection_manager=connection_manager)

        result = await service.list_interfaces(inventory_only_device_id)
        text = result[0].text

        assert "error" not in text.lower(), f"expected success, got: {text}"
        assert "port1" in text
