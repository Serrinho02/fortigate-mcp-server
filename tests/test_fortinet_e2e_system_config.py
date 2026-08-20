"""
Real end-to-end test for the new system-configuration domain (Phase A of
the "configure a FortiGate from zero" effort): exercises the real
FortiOSAdapter -> real FortiGateAPI -> real httpx.AsyncClient (only the
transport is mocked), the real ChangeService (preview -> apply, with drift
detection against the mocked "device"), and SystemService, for a device
registered only through the inventory -- the same real-wiring style as
test_fortinet_e2e_inventory_only_device.py.

Covers a DNS update (singleton resource, the new change_dispatch branch)
end to end: get current settings, preview an update, apply it, and confirm
the real FortiGateAPI sent a PUT to cmdb/system/dns with the exact payload.
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
from src.fortinet_mcp.services.change_service import ChangeService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from src.fortinet_mcp.services.system_service import SystemService
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class _FakeDevice:
    """Mutable in-memory stand-in for the FortiGate's DNS config, so the
    apply-time drift check (re-fetch current state, compare to the preview's
    snapshot) has real state to compare against."""

    def __init__(self):
        self.dns = {"primary": "8.8.8.8", "secondary": "8.8.4.4", "protocol": "cleartext"}


def _make_handler(device: _FakeDevice):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer s3cr3t-token"
        path = request.url.path

        if path.endswith("/monitor/system/status"):
            # ConnectionManager's health probe (adapter.test_connection()) hits
            # this before returning a session -- needs a 200 to succeed.
            return httpx.Response(200, json={"results": {"hostname": "CDM-OBM-HUB-FW01"}, "status": "success"})
        if path.endswith("/cmdb/system/dns") and request.method == "GET":
            return httpx.Response(200, json={"http_method": "GET", "results": device.dns, "status": "success"})
        if path.endswith("/cmdb/system/dns") and request.method == "PUT":
            import json as _json

            device.dns = _json.loads(request.content)
            return httpx.Response(200, json={"status": "success", "mkey": "dns"})
        return httpx.Response(404, json={"status": "error", "message": f"unhandled {request.method} {path}"})

    return handler


@pytest.fixture
def fake_device():
    return _FakeDevice()


@pytest.fixture(autouse=True)
def mock_fortigate_transport(monkeypatch, fake_device):
    import src.fortigate_mcp.core.fortigate as fortigate_module

    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_make_handler(fake_device))
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


@pytest.fixture
def change_service(empty_fortigate_manager, session_factory, connection_manager):
    return ChangeService(
        empty_fortigate_manager,
        session_factory,
        ModePolicy(OperatingMode.FULL),
        connection_manager=connection_manager,
    )


@pytest.fixture
def system_service(empty_fortigate_manager, change_service, connection_manager):
    return SystemService(empty_fortigate_manager, change_service, connection_manager=connection_manager)


class TestRealEndToEndDnsBootstrap:
    @pytest.mark.asyncio
    async def test_get_dns_reads_real_current_state(
        self, system_service, inventory_only_device_id, fake_device
    ):
        result = await system_service.get_dns(inventory_only_device_id)
        text = result[0].text
        assert "error" not in text.lower(), f"expected success, got: {text}"
        assert "8.8.8.8" in text

    @pytest.mark.asyncio
    async def test_update_dns_preview_then_apply_round_trips_through_real_http(
        self, system_service, change_service, inventory_only_device_id, fake_device
    ):
        new_dns = {"primary": "1.1.1.1", "secondary": "1.0.0.1", "protocol": "cleartext"}

        preview_result = await system_service.update_dns(inventory_only_device_id, new_dns)
        preview_text = preview_result[0].text
        assert "change_id" in preview_text
        assert fake_device.dns["primary"] == "8.8.8.8"  # not yet applied

        change_id = next(
            line.split("change_id:", 1)[1].strip()
            for line in preview_text.splitlines()
            if "change_id:" in line
        )
        await change_service.apply(change_id)

        assert fake_device.dns == new_dns  # the real PUT reached the fake device

        confirm_result = await system_service.get_dns(inventory_only_device_id)
        assert "1.1.1.1" in confirm_result[0].text
