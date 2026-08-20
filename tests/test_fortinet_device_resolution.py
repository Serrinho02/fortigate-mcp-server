"""
Tests for resolve_adapter: the bridge between the legacy FortiGateManager
and the inventory DB/ConnectionManager. This is the fix for the exact bug
reported in production use: a device registered only via
inventory.register_device_pending was invisible to get_device_status,
list_interfaces, analysis.*, vpn.*, etc.
"""
import keyring
import pytest
import pytest_asyncio

from src.fortinet_mcp.adapters.registry import AdapterRegistry
from src.fortinet_mcp.errors import CredentialNotProvisionedError
from src.fortinet_mcp.infra.connection_manager import ConnectionManager
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.repositories.inventory_repository import InventoryRepository
from src.fortinet_mcp.services.device_resolution import resolve_adapter
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


class FakeAdapter:
    product_type = "fortios"

    async def test_connection(self) -> bool:
        return True

    async def close(self) -> None:
        pass


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
    reg.register("fortios", lambda client: FakeAdapter())
    return reg


@pytest.fixture
def connection_manager(session_factory, credentials, registry):
    return ConnectionManager(session_factory, credentials, registry)


class TestLegacyResolution:
    @pytest.mark.asyncio
    async def test_resolves_via_legacy_manager_when_present(self, fortigate_manager, mock_fortigate_api):
        fortigate_manager.devices["legacy_id"] = mock_fortigate_api

        adapter = await resolve_adapter("legacy_id", fortigate_manager, connection_manager=None)

        assert adapter is not None

    @pytest.mark.asyncio
    async def test_legacy_lookup_takes_priority_over_inventory(
        self, fortigate_manager, mock_fortigate_api, connection_manager, session_factory, credentials
    ):
        # Same id happens to exist in both systems -- legacy must win (no
        # network round-trip needed, and it's the pre-existing behavior).
        fortigate_manager.devices["dual"] = mock_fortigate_api

        adapter = await resolve_adapter("dual", fortigate_manager, connection_manager)

        assert adapter is not None
        # No inventory session should have been opened for a purely-legacy id.
        assert connection_manager.list_active() == []


class TestInventoryFallback:
    @pytest.mark.asyncio
    async def test_resolves_via_inventory_when_not_in_legacy_manager(
        self, fortigate_manager, connection_manager, session_factory, credentials
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            device = await inventory.register_device_pending("Alfa", "Milano", "fw01", "10.0.0.1")
            await session.commit()
            device_id, credential_id = device.id, device.credential_id
        credentials.set_secret(credential_id, auth_type="token", api_token="s3cr3t")

        # This is the exact bug: fortigate_manager knows nothing about this
        # device (config.json has no entry for it) -- it only exists in inventory.
        adapter = await resolve_adapter(device_id, fortigate_manager, connection_manager)

        assert isinstance(adapter, FakeAdapter)

    @pytest.mark.asyncio
    async def test_surfaces_credential_not_provisioned_instead_of_generic_not_found(
        self, fortigate_manager, connection_manager, session_factory, credentials
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            device = await inventory.register_device_pending("Alfa", "Milano", "fw02", "10.0.0.2")
            await session.commit()
            device_id = device.id
        # deliberately never provisioning the credential

        with pytest.raises(ValueError, match="not been provisioned yet"):
            await resolve_adapter(device_id, fortigate_manager, connection_manager)

    @pytest.mark.asyncio
    async def test_surfaces_ambiguous_target_instead_of_generic_not_found(
        self, fortigate_manager, connection_manager, session_factory, credentials
    ):
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            d1 = await inventory.register_device_pending("Alfa", "Milano", "fw01", "10.0.0.1")
            d2 = await inventory.register_device_pending("Alfa", "Milano", "fw02", "10.0.0.2")
            await session.commit()
        credentials.set_secret(d1.credential_id, auth_type="token", api_token="x")
        credentials.set_secret(d2.credential_id, auth_type="token", api_token="x")

        with pytest.raises(ValueError, match="matches multiple devices"):
            await resolve_adapter("Milano", fortigate_manager, connection_manager)


class TestNotFoundAnywhere:
    @pytest.mark.asyncio
    async def test_not_in_legacy_and_no_connection_manager_raises_clear_error(self, fortigate_manager):
        with pytest.raises(ValueError, match="not found in legacy config or inventory"):
            await resolve_adapter("nope", fortigate_manager, connection_manager=None)

    @pytest.mark.asyncio
    async def test_not_in_legacy_or_inventory_raises_clear_error(self, fortigate_manager, connection_manager):
        with pytest.raises(ValueError, match="not found in legacy config or inventory"):
            await resolve_adapter("totally-unknown", fortigate_manager, connection_manager)
