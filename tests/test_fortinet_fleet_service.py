"""
Tests for FleetService: multi-device compare/search/sync/replicate/report,
resolved through ConnectionManager/the inventory DB (not the legacy
FortiGateManager). Uses a FakeAdapter with in-memory per-device data
(keyed by the inventory Device.id, matching what ConnectionManager
actually constructs) -- no real HTTP, no real keyring.
"""
import json

import keyring
import pytest
import pytest_asyncio

from src.fortinet_mcp.adapters.registry import AdapterRegistry
from src.fortinet_mcp.infra.connection_manager import ConnectionManager
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.repositories.inventory_repository import InventoryRepository
from src.fortinet_mcp.services.fleet_service import FleetService
from src.fortinet_mcp.services.mode_policy import ModePolicy, OperatingMode
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class FakeAdapter:
    product_type = "fortios"

    def __init__(self, data: dict):
        self.data = data
        self.closed = False

    async def test_connection(self) -> bool:
        return True

    async def close(self) -> None:
        self.closed = True

    async def list_policies(self, vdom=None):
        return {"results": self.data.get("firewall_policy", [])}

    async def list_address_objects(self, vdom=None):
        return {"results": self.data.get("address_object", [])}

    async def list_service_objects(self, vdom=None):
        return {"results": self.data.get("service_object", [])}

    async def list_virtual_ips(self, vdom=None):
        return {"results": self.data.get("virtual_ip", [])}

    async def create_address_object(self, data, vdom=None):
        self.data.setdefault("address_object", []).append(data)
        return {"status": "success"}

    async def create_service_object(self, data, vdom=None):
        self.data.setdefault("service_object", []).append(data)
        return {"status": "success"}


def _empty_data() -> dict:
    return {"firewall_policy": [], "address_object": [], "service_object": [], "virtual_ip": []}


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
def device_data_store():
    return {}


@pytest.fixture
def registry(device_data_store):
    reg = AdapterRegistry()

    def factory(client):
        data = device_data_store.setdefault(client.device_id, _empty_data())
        return FakeAdapter(data)

    reg.register("fortios", factory)
    return reg


async def _register_device(session_factory, credentials, customer, site, name, host) -> str:
    async with session_factory() as session:
        inventory = InventoryRepository(session)
        device = await inventory.register_device_pending(customer, site, name, host)
        await session.commit()
        device_id, credential_id = device.id, device.credential_id
    credentials.set_secret(credential_id, auth_type="token", api_token="s3cr3t")
    return device_id


@pytest.fixture
def connection_manager(session_factory, credentials, registry):
    return ConnectionManager(session_factory, credentials, registry)


@pytest.fixture
def mode_policy():
    return ModePolicy(OperatingMode.FULL)


@pytest.fixture
def fleet_service(connection_manager, mode_policy):
    return FleetService(connection_manager, mode_policy)


def _text(result) -> str:
    return result[0].text


def _json(result) -> dict:
    return json.loads(_text(result).split("\n\n", 1)[1])


class TestCompareDevices:
    @pytest.mark.asyncio
    async def test_compares_address_objects_between_two_devices(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw02", "10.0.0.2")
        device_data_store[id_a] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_b] = _empty_data()

        result = await fleet_service.compare_devices("fw01", "fw02", resource_type="address_object")

        data = _json(result)
        assert data["only_in_a"] == ["web1"]
        assert data["device_a"] == "fw01"
        assert data["device_b"] == "fw02"

    @pytest.mark.asyncio
    async def test_ambiguous_target_returns_error(self, fleet_service, session_factory, credentials):
        await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        await _register_device(session_factory, credentials, "Alfa", "Milano", "fw02", "10.0.0.2")

        result = await fleet_service.compare_devices("Milano", "fw01")

        assert "error" in _text(result).lower()


class TestSearchObject:
    @pytest.mark.asyncio
    async def test_finds_object_across_customer_devices(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw02", "10.0.0.2")
        device_data_store[id_a] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_b] = _empty_data()

        result = await fleet_service.search_object("web1", resource_type="address_object", target="Alfa")

        data = _json(result)
        matches = {m["device"]: m for m in data["matches"]}
        assert matches["fw01"]["found"] is True
        assert matches["fw02"]["found"] is False

    @pytest.mark.asyncio
    async def test_no_target_searches_entire_inventory(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Beta", "Torino", "fw02", "10.0.0.2")
        device_data_store[id_a] = _empty_data()
        device_data_store[id_b] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}

        result = await fleet_service.search_object("web1", resource_type="address_object")

        data = _json(result)
        assert len(data["matches"]) == 2
        matches = {m["device"]: m for m in data["matches"]}
        assert matches["fw02"]["found"] is True


class TestSyncObjects:
    @pytest.mark.asyncio
    async def test_dry_run_reports_plan_without_writing(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw02", "10.0.0.2")
        device_data_store[id_a] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_b] = _empty_data()

        result = await fleet_service.sync_objects("fw01", "fw02", resource_type="address_object")

        data = _json(result)
        assert data["objects_to_create"] == ["web1"]
        assert device_data_store[id_b]["address_object"] == []  # nothing written
        assert "dry run" in _text(result).lower()

    @pytest.mark.asyncio
    async def test_confirm_true_executes_the_sync(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw02", "10.0.0.2")
        device_data_store[id_a] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_b] = _empty_data()

        result = await fleet_service.sync_objects("fw01", "fw02", resource_type="address_object", confirm=True)

        data = _json(result)
        assert data["results"] == [{"name": "web1", "status": "created"}]
        assert device_data_store[id_b]["address_object"] == [{"name": "web1", "subnet": "10.0.0.0/24"}]

    @pytest.mark.asyncio
    async def test_confirm_true_blocked_in_read_only_mode(
        self, connection_manager, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw02", "10.0.0.2")
        device_data_store[id_a] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_b] = _empty_data()
        read_only_service = FleetService(connection_manager, ModePolicy(OperatingMode.READ_ONLY))

        result = await read_only_service.sync_objects("fw01", "fw02", resource_type="address_object", confirm=True)

        assert "read_only" in _text(result).lower()
        assert device_data_store[id_b]["address_object"] == []


class TestReplicateConfig:
    @pytest.mark.asyncio
    async def test_dry_run_plan_across_multiple_destinations(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_src = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw-src", "10.0.0.1")
        id_d1 = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw-d1", "10.0.0.2")
        id_d2 = await _register_device(session_factory, credentials, "Alfa", "Torino", "fw-d2", "10.0.0.3")
        device_data_store[id_src] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_d1] = _empty_data()
        device_data_store[id_d2] = _empty_data()

        result = await fleet_service.replicate_config("fw-src", "Alfa", resource_types=["address_object"])

        data = _json(result)
        device_names = {d["device"] for d in data["devices"]}
        assert device_names == {"fw-d1", "fw-d2"}  # source excluded from its own destination scope
        for d in data["devices"]:
            assert d["address_object"]["objects_to_create"] == ["web1"]

    @pytest.mark.asyncio
    async def test_confirm_true_executes_across_destinations(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_src = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw-src", "10.0.0.1")
        id_d1 = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw-d1", "10.0.0.2")
        device_data_store[id_src] = {**_empty_data(), "address_object": [{"name": "web1", "subnet": "10.0.0.0/24"}]}
        device_data_store[id_d1] = _empty_data()

        await fleet_service.replicate_config(
            "fw-src", "Alfa", resource_types=["address_object"], confirm=True
        )

        assert device_data_store[id_d1]["address_object"] == [{"name": "web1", "subnet": "10.0.0.0/24"}]


class TestReport:
    @pytest.mark.asyncio
    async def test_reports_score_per_device_and_summary(
        self, fleet_service, session_factory, credentials, device_data_store
    ):
        id_a = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.0.0.1")
        id_b = await _register_device(session_factory, credentials, "Alfa", "Roma", "fw02", "10.0.0.2")
        device_data_store[id_a] = _empty_data()
        device_data_store[id_b] = {
            **_empty_data(),
            "firewall_policy": [
                {
                    "policyid": 1, "srcintf": [{"name": "port1"}], "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "action": "accept", "status": "enable",
                }
            ],
        }

        result = await fleet_service.report("Alfa")

        data = _json(result)
        assert data["summary"]["device_count"] == 2
        assert data["summary"]["reachable_device_count"] == 2
        scores = {d["device"]: d["security_score"]["score"] for d in data["devices"]}
        assert scores["fw01"] == 100  # no policies, perfect score
        assert scores["fw02"] < 100  # any-any-any policy present
