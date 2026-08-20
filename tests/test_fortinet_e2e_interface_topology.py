"""
Real end-to-end test for Phase C of the "configure a FortiGate from zero"
effort: creating a VLAN interface, assigning it to a zone, and standing up
a DHCP server on it -- through the real FortiOSAdapter -> real
FortiGateAPI -> real httpx.AsyncClient (only the transport is mocked) and
the real ChangeService (preview -> apply), for a device registered only
through the inventory. Same real-wiring style as
test_fortinet_e2e_system_config.py / test_fortinet_e2e_vdom_lifecycle.py.

This mirrors a realistic "from zero" bootstrap step: a VLAN sub-interface
carved out of a physical port, grouped into a zone, with DHCP handed out to
clients on it.
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
from src.fortinet_mcp.services.routing_service import RoutingService
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class _FakeDevice:
    def __init__(self):
        self.interfaces: dict = {}
        self.zones: dict = {}
        self.dhcp_servers: dict = {}
        self._next_dhcp_id = 1


def _make_handler(device: _FakeDevice):
    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        assert request.headers.get("Authorization") == "Bearer s3cr3t-token"
        path = request.url.path
        method = request.method

        if path.endswith("/monitor/system/status"):
            return httpx.Response(200, json={"results": {"hostname": "fw01"}, "status": "success"})

        if path.endswith("/cmdb/system/interface") and method == "POST":
            data = _json.loads(request.content)
            device.interfaces[data["name"]] = data
            return httpx.Response(200, json={"status": "success", "mkey": data["name"]})

        if "/cmdb/system/interface/" in path and method == "GET":
            name = path.rsplit("/", 1)[-1]
            iface = device.interfaces.get(name)
            if iface is None:
                return httpx.Response(404, json={"status": "error", "message": "not found"})
            return httpx.Response(200, json={"results": iface, "status": "success"})

        if path.endswith("/cmdb/system/zone") and method == "POST":
            data = _json.loads(request.content)
            device.zones[data["name"]] = data
            return httpx.Response(200, json={"status": "success", "mkey": data["name"]})

        if path.endswith("/cmdb/system.dhcp/server") and method == "POST":
            data = _json.loads(request.content)
            server_id = str(device._next_dhcp_id)
            device._next_dhcp_id += 1
            device.dhcp_servers[server_id] = data
            return httpx.Response(200, json={"status": "success", "mkey": server_id})

        if path.endswith("/cmdb/system.dhcp/server"):
            return httpx.Response(
                200, json={"results": list(device.dhcp_servers.values()), "status": "success"}
            )

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
def routing_service(empty_fortigate_manager, change_service, connection_manager):
    return RoutingService(empty_fortigate_manager, change_service, connection_manager=connection_manager)


def _change_id_from(result) -> str:
    for line in result[0].text.splitlines():
        if "change_id:" in line:
            return line.split("change_id:", 1)[1].strip()
    raise AssertionError(f"no change_id found in: {result[0].text}")


class TestRealEndToEndInterfaceTopology:
    @pytest.mark.asyncio
    async def test_create_vlan_interface_zone_and_dhcp_server_round_trip(
        self, routing_service, change_service, inventory_only_device_id, fake_device
    ):
        # 1. Carve a VLAN sub-interface out of a physical port, with an IP.
        iface_data = {
            "name": "vlan100",
            "type": "vlan",
            "interface": "port2",
            "vlanid": 100,
            "ip": "10.10.100.1 255.255.255.0",
        }
        preview = await routing_service.create_interface(inventory_only_device_id, iface_data)
        assert "vlan100" not in fake_device.interfaces  # not yet applied
        await change_service.apply(_change_id_from(preview))
        assert fake_device.interfaces["vlan100"]["ip"] == "10.10.100.1 255.255.255.0"

        # 2. Group it into a zone.
        zone_data = {"name": "guest", "interface": [{"interface-name": "vlan100"}]}
        preview = await routing_service.create_zone(inventory_only_device_id, zone_data)
        await change_service.apply(_change_id_from(preview))
        assert fake_device.zones["guest"]["interface"] == [{"interface-name": "vlan100"}]

        # 3. Stand up DHCP on it.
        dhcp_data = {
            "interface": "vlan100",
            "ip-range": [{"start-ip": "10.10.100.10", "end-ip": "10.10.100.200"}],
            "netmask": "255.255.255.0",
            "default-gateway": "10.10.100.1",
        }
        preview = await routing_service.create_dhcp_server(inventory_only_device_id, dhcp_data)
        await change_service.apply(_change_id_from(preview))
        assert len(fake_device.dhcp_servers) == 1
        (created_server,) = fake_device.dhcp_servers.values()
        assert created_server["interface"] == "vlan100"

        # 4. Confirm everything is visible read-back through the same service.
        list_result = await routing_service.list_dhcp_servers(inventory_only_device_id)
        assert "error" not in list_result[0].text.lower()
