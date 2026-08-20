"""
Tests for the Phase 1 inventory store: ORM schema, InventoryRepository,
and DeviceResolver. Uses an in-memory SQLite database per test -- never
touches the file at config/inventory.db.
"""
import pytest
import pytest_asyncio

from src.fortinet_mcp.errors import AmbiguousTargetError, DeviceNotFoundError, DuplicateNameError
from src.fortinet_mcp.infra.db import create_engine, create_session_factory, init_models
from src.fortinet_mcp.infra.device_resolver import DeviceResolver
from src.fortinet_mcp.repositories.inventory_repository import InventoryRepository


@pytest_asyncio.fixture
async def session():
    engine = create_engine("sqlite+aiosqlite:///:memory:")
    await init_models(engine)
    session_factory = create_session_factory(engine)
    async with session_factory() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture
async def repo(session):
    return InventoryRepository(session)


class TestInventoryRepositoryCustomersAndSites:
    @pytest.mark.asyncio
    async def test_get_or_create_customer_creates_once(self, repo):
        c1 = await repo.get_or_create_customer("Alfa")
        c2 = await repo.get_or_create_customer("Alfa")
        assert c1.id == c2.id
        assert (await repo.list_customers()) == [c1]

    @pytest.mark.asyncio
    async def test_get_or_create_site_scoped_to_customer(self, repo):
        alfa = await repo.get_or_create_customer("Alfa")
        beta = await repo.get_or_create_customer("Beta")
        site_a = await repo.get_or_create_site(alfa.id, "Milano")
        site_b = await repo.get_or_create_site(beta.id, "Milano")
        assert site_a.id != site_b.id
        assert await repo.list_sites(alfa.id) == [site_a]


class TestInventoryRepositoryDevices:
    @pytest.mark.asyncio
    async def test_register_device_pending_creates_hierarchy(self, repo):
        device = await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.1")

        assert device.credential_id is not None
        assert device.name == "fw01"
        assert device.mgmt_host == "10.10.10.1"

        customers = await repo.list_customers()
        assert [c.name for c in customers] == ["Alfa"]

    @pytest.mark.asyncio
    async def test_duplicate_device_name_in_same_site_raises(self, repo):
        await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.1")
        with pytest.raises(DuplicateNameError):
            await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.2")

    @pytest.mark.asyncio
    async def test_same_device_name_allowed_in_different_sites(self, repo):
        d1 = await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.1")
        d2 = await repo.register_device_pending("Alfa", "Roma", "fw01", "10.10.20.1")
        assert d1.id != d2.id

    @pytest.mark.asyncio
    async def test_list_devices_filtered_by_customer(self, repo):
        alfa_dev = await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.1")
        await repo.register_device_pending("Beta", "Torino", "fw02", "10.10.20.1")

        alfa = await repo.get_customer_by_name("Alfa")
        devices = await repo.list_devices(customer_id=alfa.id)

        assert [d.id for d in devices] == [alfa_dev.id]

    @pytest.mark.asyncio
    async def test_remove_device(self, repo):
        device = await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.1")
        await repo.remove_device(device.id)
        assert await repo.get_device(device.id) is None

    @pytest.mark.asyncio
    async def test_remove_unknown_device_raises(self, repo):
        with pytest.raises(LookupError):
            await repo.remove_device("dev_doesnotexist")


class TestDeviceResolver:
    @pytest_asyncio.fixture
    async def resolver(self, repo):
        await repo.register_device_pending("Alfa", "Milano", "fw01", "10.10.10.1")
        await repo.register_device_pending("Alfa", "Milano", "fw02", "10.10.10.2")
        await repo.register_device_pending("Alfa", "Roma", "fw-roma", "10.10.20.1")
        await repo.register_device_pending("Beta", "Torino", "fw-beta", "10.10.30.1")
        return DeviceResolver(repo)

    @pytest.mark.asyncio
    async def test_resolve_by_literal_host(self, resolver):
        matches = await resolver.resolve("10.10.10.1")
        assert [d.name for d in matches] == ["fw01"]

    @pytest.mark.asyncio
    async def test_resolve_by_exact_device_name(self, resolver):
        matches = await resolver.resolve("fw01")
        assert [d.name for d in matches] == ["fw01"]

    @pytest.mark.asyncio
    async def test_resolve_by_exact_device_name_case_insensitive(self, resolver):
        matches = await resolver.resolve("FW01")
        assert [d.name for d in matches] == ["fw01"]

    @pytest.mark.asyncio
    async def test_resolve_by_site_name_returns_all_devices_in_site(self, resolver):
        matches = await resolver.resolve("Milano")
        assert sorted(d.name for d in matches) == ["fw01", "fw02"]

    @pytest.mark.asyncio
    async def test_resolve_by_customer_name_returns_all_devices_under_customer(self, resolver):
        matches = await resolver.resolve("Alfa")
        assert sorted(d.name for d in matches) == ["fw-roma", "fw01", "fw02"]

    @pytest.mark.asyncio
    async def test_resolve_by_device_name_prefix(self, resolver):
        matches = await resolver.resolve("fw-ro")
        assert [d.name for d in matches] == ["fw-roma"]

    @pytest.mark.asyncio
    async def test_ambiguous_exact_customer_name_matching_multiple_devices_is_fine(self, resolver):
        # "Alfa" is a customer with 3 devices -- not ambiguous, it's a fan-out target.
        matches = await resolver.resolve("alfa")
        assert len(matches) == 3

    @pytest.mark.asyncio
    async def test_ambiguous_device_name_prefix_raises(self, resolver):
        with pytest.raises(AmbiguousTargetError) as exc_info:
            await resolver.resolve("fw0")
        assert set(exc_info.value.candidates) == {"fw01", "fw02"}

    @pytest.mark.asyncio
    async def test_unknown_target_raises_not_found(self, resolver):
        with pytest.raises(DeviceNotFoundError):
            await resolver.resolve("nonexistent")

    @pytest.mark.asyncio
    async def test_empty_target_raises_value_error(self, resolver):
        with pytest.raises(ValueError):
            await resolver.resolve("   ")

    @pytest.mark.asyncio
    async def test_resolve_one_raises_when_ambiguous(self, resolver):
        with pytest.raises(AmbiguousTargetError):
            await resolver.resolve_one("Alfa")

    @pytest.mark.asyncio
    async def test_resolve_one_returns_single_device(self, resolver):
        device = await resolver.resolve_one("fw01")
        assert device.name == "fw01"
