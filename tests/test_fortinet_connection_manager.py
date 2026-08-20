"""
Tests for ConnectionManager. Uses a fake adapter registered in a
per-test AdapterRegistry (never the real FortiOSAdapter/httpx chain --
that's already covered by test_fortinet_adapters.py and the pre-existing
FortiGateAPI tests) and the fake in-memory keyring backend from
test_fortinet_credential_manager.py.

Backed by a temp-file SQLite database (not ":memory:") so the
session_factory ConnectionManager uses internally and the fixture setup
below see the same persisted data across separate short-lived sessions.
"""
import keyring
import pytest
import pytest_asyncio

from src.fortinet_mcp.adapters.registry import AdapterRegistry
from src.fortinet_mcp.errors import AmbiguousTargetError, CredentialNotProvisionedError, DeviceConnectionError
from src.fortinet_mcp.infra.connection_manager import ConnectionManager
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.repositories.inventory_repository import InventoryRepository
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class FakeAdapter:
    """Stands in for FortiOSAdapter -- no real HTTP, controllable health check."""

    product_type = "fortios"

    def __init__(self, healthy: bool = True):
        self.healthy = healthy
        self.closed = False

    async def test_connection(self) -> bool:
        return self.healthy

    async def close(self) -> None:
        self.closed = True


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
def healthy_registry():
    registry = AdapterRegistry()
    registry.register("fortios", lambda client: FakeAdapter(healthy=True))
    return registry


@pytest.fixture
def unhealthy_registry():
    registry = AdapterRegistry()
    registry.register("fortios", lambda client: FakeAdapter(healthy=False))
    return registry


async def _register_device(session_factory, credentials, customer, site, name, host, *, provision=True):
    async with session_factory() as session:
        inventory = InventoryRepository(session)
        device = await inventory.register_device_pending(customer, site, name, host)
        await session.commit()
        device_id = device.id
        credential_id = device.credential_id
    if provision:
        credentials.set_secret(credential_id, auth_type="token", api_token="s3cr3t")
    return device_id


@pytest_asyncio.fixture
async def device_with_credential(session_factory, credentials):
    device_id = await _register_device(session_factory, credentials, "Alfa", "Milano", "fw01", "10.10.10.1")
    return device_id


class TestConnectionManagerConnect:
    @pytest.mark.asyncio
    async def test_connect_by_device_name_builds_session_with_full_metadata(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)

        session = await manager.connect("fw01")

        assert session.device_id == device_with_credential
        assert session.customer_name == "Alfa"
        assert session.site_name == "Milano"
        assert session.device_name == "fw01"
        assert session.mgmt_host == "10.10.10.1"
        assert session.vdom == "root"
        assert isinstance(session.adapter, FakeAdapter)

    @pytest.mark.asyncio
    async def test_connect_reuses_cached_session(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)

        first = await manager.connect("fw01")
        second = await manager.connect("fw01")

        assert first is second

    @pytest.mark.asyncio
    async def test_connect_without_provisioned_credential_raises(
        self, session_factory, credentials, healthy_registry
    ):
        await _register_device(
            session_factory, credentials, "Alfa", "Milano", "fw02", "10.10.10.2", provision=False
        )
        manager = ConnectionManager(session_factory, credentials, healthy_registry)

        with pytest.raises(CredentialNotProvisionedError):
            await manager.connect("fw02")

    @pytest.mark.asyncio
    async def test_connect_with_failed_health_probe_raises_and_closes_adapter(
        self, session_factory, credentials, unhealthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, unhealthy_registry)

        with pytest.raises(DeviceConnectionError):
            await manager.connect("fw01")

        assert manager.list_active() == []

    @pytest.mark.asyncio
    async def test_connect_by_customer_name_with_multiple_devices_is_ambiguous(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        await _register_device(session_factory, credentials, "Alfa", "Roma", "fw03", "10.10.30.1")
        manager = ConnectionManager(session_factory, credentials, healthy_registry)

        with pytest.raises(AmbiguousTargetError):
            await manager.connect("Alfa")


class TestConnectionManagerLifecycle:
    @pytest.mark.asyncio
    async def test_disconnect_closes_adapter_and_clears_cache(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)
        session = await manager.connect("fw01")

        await manager.disconnect(device_with_credential)

        assert session.adapter.closed is True
        assert manager.list_active() == []

    @pytest.mark.asyncio
    async def test_disconnect_all(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        await _register_device(session_factory, credentials, "Alfa", "Roma", "fw03", "10.10.30.1")
        manager = ConnectionManager(session_factory, credentials, healthy_registry)
        await manager.connect("fw01")
        await manager.connect("fw03")

        await manager.disconnect_all()

        assert manager.list_active() == []

    @pytest.mark.asyncio
    async def test_list_active_reflects_open_sessions(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)
        assert manager.list_active() == []

        await manager.connect("fw01")

        assert len(manager.list_active()) == 1

    @pytest.mark.asyncio
    async def test_evict_idle_drops_stale_sessions(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)
        session = await manager.connect("fw01")
        session.last_used_at -= 1000  # simulate a session idle for a long time

        evicted = manager.evict_idle(idle_timeout_seconds=1)

        assert evicted == [session]
        assert manager.list_active() == []

    @pytest.mark.asyncio
    async def test_evict_idle_keeps_recently_used_sessions(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)
        await manager.connect("fw01")

        evicted = manager.evict_idle(idle_timeout_seconds=900)

        assert evicted == []
        assert len(manager.list_active()) == 1


class TestListAllDevices:
    @pytest.mark.asyncio
    async def test_returns_every_device_regardless_of_customer(
        self, session_factory, credentials, healthy_registry, device_with_credential
    ):
        await _register_device(session_factory, credentials, "Beta", "Torino", "fw-beta", "10.10.40.1")
        manager = ConnectionManager(session_factory, credentials, healthy_registry)

        devices = await manager.list_all_devices()

        assert sorted(d.name for d in devices) == ["fw-beta", "fw01"]

    @pytest.mark.asyncio
    async def test_empty_inventory_returns_empty_list(self, session_factory, credentials, healthy_registry):
        manager = ConnectionManager(session_factory, credentials, healthy_registry)
        assert await manager.list_all_devices() == []
