"""
Real end-to-end test for Phase B of the "configure a FortiGate from zero"
effort: VDOM creation and inter-VDOM link creation, through the real
FortiOSAdapter -> real FortiGateAPI -> real httpx.AsyncClient (only the
transport is mocked) and the real ChangeService (preview -> apply, with
drift detection against the mocked device), for a device registered only
through the inventory -- same real-wiring style as
test_fortinet_e2e_system_config.py.
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
from src.fortinet_mcp.services.vdom_service import VdomService
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class _FakeDevice:
    def __init__(self):
        self.vdoms: dict = {}
        self.vdom_links: dict = {}


def _make_handler(device: _FakeDevice):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer s3cr3t-token"
        path = request.url.path
        method = request.method

        if path.endswith("/monitor/system/status"):
            return httpx.Response(200, json={"results": {"hostname": "fw01"}, "status": "success"})

        if path.endswith("/cmdb/system/vdom") and method == "POST":
            import json as _json

            data = _json.loads(request.content)
            device.vdoms[data["name"]] = data
            return httpx.Response(200, json={"status": "success", "mkey": data["name"]})

        if path.endswith("/cmdb/system/vdom-link") and method == "POST":
            import json as _json

            data = _json.loads(request.content)
            device.vdom_links[data["name"]] = data
            return httpx.Response(200, json={"status": "success", "mkey": data["name"]})

        if path.endswith("/cmdb/system/vdom-link") and method == "GET":
            return httpx.Response(
                200, json={"results": list(device.vdom_links.values()), "status": "success"}
            )

        if "/cmdb/system/vdom-link/" in path and method == "GET":
            name = path.rsplit("/", 1)[-1]
            link = device.vdom_links.get(name)
            if link is None:
                return httpx.Response(404, json={"status": "error", "message": "not found"})
            return httpx.Response(200, json={"results": link, "status": "success"})

        return httpx.Response(404, json={"status": "error", "message": f"unhandled {method} {path}"})

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
        device = await inventory.register_device_pending("CDM", "OBM-HUB", "fw01", "10.89.255.1")
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
def vdom_service(empty_fortigate_manager, change_service, connection_manager):
    return VdomService(empty_fortigate_manager, change_service, connection_manager=connection_manager)


class TestRealEndToEndVdomLifecycle:
    @pytest.mark.asyncio
    async def test_create_vdom_round_trips_through_real_http(
        self, vdom_service, change_service, inventory_only_device_id, fake_device
    ):
        preview_result = await vdom_service.create_vdom(inventory_only_device_id, {"name": "Alfa"})
        assert "change_id" in preview_result[0].text
        assert "Alfa" not in fake_device.vdoms  # not yet applied

        change_id = next(
            line.split("change_id:", 1)[1].strip()
            for line in preview_result[0].text.splitlines()
            if "change_id:" in line
        )
        await change_service.apply(change_id)

        assert "Alfa" in fake_device.vdoms  # the real POST reached the fake device

    @pytest.mark.asyncio
    async def test_create_vdom_link_round_trips_through_real_http(
        self, vdom_service, change_service, inventory_only_device_id, fake_device
    ):
        preview_result = await vdom_service.create_vdom_link(inventory_only_device_id, {"name": "link1"})
        change_id = next(
            line.split("change_id:", 1)[1].strip()
            for line in preview_result[0].text.splitlines()
            if "change_id:" in line
        )
        await change_service.apply(change_id)

        assert "link1" in fake_device.vdom_links

        list_result = await vdom_service.list_vdom_links(inventory_only_device_id)
        assert "error" not in list_result[0].text.lower()
