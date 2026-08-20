"""
Real end-to-end regression test for the exact production bug report:

    "get_device_status e list_interfaces falliscono con Resource not found
    ... per un device registrato solo tramite l'inventario"
    (device dev_a83653612dc2, CDM-OBM-HUB-FW01, 10.89.255.1)

Unlike test_fortinet_service_inventory_fallback.py (which uses a hand-rolled
fake adapter), this test exercises the REAL production wiring end to end:
the real FortiOSAdapter -> real FortiGateAPI -> real httpx.AsyncClient (only
its transport is swapped for an in-process handler standing in for the
physical FortiGate), the real ConnectionManager/CredentialManager/
InventoryRepository, and the same DeviceService/RoutingService construction
server.py uses. The only thing not real is the network socket.

The device is registered ONLY through InventoryRepository.register_device_pending
(inventory.register_device_pending's underlying call) -- the legacy
FortiGateManager is left completely empty, exactly matching how the user's
device was added. Before the fix, this raised "Resource not found" from
DeviceService.get_device_status / RoutingService.list_interfaces even
though the device was perfectly reachable (connection.connect worked).
"""
import httpx
import keyring
import pytest
import pytest_asyncio

from src.fortigate_mcp.config.models import AuthConfig
from src.fortigate_mcp.core.fortigate import FortiGateManager
from src.fortinet_mcp.adapters.fortios.factory import register_fortios_adapter
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


def _fake_fortigate_handler(request: httpx.Request) -> httpx.Response:
    """Stands in for the physical FortiGate's REST API."""
    assert request.headers.get("Authorization") == "Bearer s3cr3t-token"
    path = request.url.path

    if path.endswith("/monitor/system/status"):
        return httpx.Response(
            200,
            json={
                "http_method": "GET",
                "results": {"hostname": "CDM-OBM-HUB-FW01", "model_name": "FortiGate", "model_number": "100F"},
                "version": "v7.4.0",
                "serial": "FGT-E2E-001",
                "status": "success",
            },
        )
    if path.endswith("/cmdb/system/interface"):
        return httpx.Response(
            200,
            json={
                "http_method": "GET",
                "results": [{"name": "port1", "status": "up"}, {"name": "port2", "status": "down"}],
                "status": "success",
            },
        )
    return httpx.Response(404, json={"status": "error", "message": f"unhandled path {path}"})


@pytest.fixture(autouse=True)
def mock_fortigate_transport(monkeypatch):
    """Swap only the network transport of the real httpx.AsyncClient every
    FortiGateAPI instance creates -- everything above the socket (auth
    headers, URL building, response parsing, adapter, service layer) is the
    real production code path."""
    import src.fortigate_mcp.core.fortigate as fortigate_module

    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_fake_fortigate_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(fortigate_module.httpx, "AsyncClient", patched_async_client)


@pytest_asyncio.fixture
async def session_factory(tmp_path):
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'inventory.db').as_posix()}"
    engine = create_engine(db_url)
    await init_models(engine)
    factory = create_session_factory(engine)
    yield factory
    await engine.dispose()


@pytest.fixture
def empty_fortigate_manager():
    """The legacy manager, deliberately left empty -- config.json has no
    entry for this device, matching the real bug report exactly."""
    return FortiGateManager({}, AuthConfig(require_auth=False, api_tokens=[], allowed_origins=[]))


@pytest.fixture
def connection_manager(session_factory):
    registry = AdapterRegistry()
    register_fortios_adapter(registry)
    credentials = CredentialManager()
    return ConnectionManager(session_factory, credentials, registry)


@pytest_asyncio.fixture
async def inventory_only_device_id(session_factory, connection_manager):
    async with session_factory() as session:
        inventory = InventoryRepository(session)
        device = await inventory.register_device_pending(
            "CDM", "OBM-HUB", "CDM-OBM-HUB-FW01", "10.89.255.1"
        )
        await session.commit()
        device_id, credential_id = device.id, device.credential_id
    connection_manager._credentials.set_secret(credential_id, auth_type="token", api_token="s3cr3t-token")
    return device_id


class TestRealEndToEndInventoryOnlyDevice:
    @pytest.mark.asyncio
    async def test_get_device_status_works_for_device_never_added_to_legacy_manager(
        self, empty_fortigate_manager, connection_manager, inventory_only_device_id
    ):
        assert empty_fortigate_manager.devices == {}  # sanity: truly not in legacy config

        service = DeviceService(empty_fortigate_manager, connection_manager=connection_manager)
        result = await service.get_device_status(inventory_only_device_id)
        text = result[0].text

        assert "error" not in text.lower(), f"expected success, got: {text}"
        assert "CDM-OBM-HUB-FW01" in text
        assert "v7.4.0" in text

    @pytest.mark.asyncio
    async def test_list_interfaces_works_for_device_never_added_to_legacy_manager(
        self, empty_fortigate_manager, connection_manager, inventory_only_device_id
    ):
        service = RoutingService(empty_fortigate_manager, change_service=None, connection_manager=connection_manager)
        result = await service.list_interfaces(inventory_only_device_id)
        text = result[0].text

        assert "error" not in text.lower(), f"expected success, got: {text}"
        assert "port1" in text
