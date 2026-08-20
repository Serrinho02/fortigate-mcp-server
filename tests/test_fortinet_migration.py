"""
Tests for the config.json -> inventory DB + keyring migration helper.
Uses a temp JSON file (never the real config/config.json) and the fake
in-memory keyring backend -- never touches the real OS credential store.
"""
import json

import keyring
import pytest

from src.fortinet_mcp.infra import migration
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from src.fortinet_mcp.infra.db import create_engine as real_create_engine
from src.fortinet_mcp.infra.db import create_session_factory
from src.fortinet_mcp.repositories.inventory_repository import InventoryRepository
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


@pytest.fixture
def legacy_config_file(tmp_path):
    config = {
        "fortigate": {
            "devices": {
                "default": {
                    "host": "192.168.1.1",
                    "port": 443,
                    "api_token": "legacy-token-1",
                    "vdom": "root",
                    "verify_ssl": False,
                    "timeout": 30,
                },
                "backup": {
                    "host": "192.168.1.2",
                    "username": "admin",
                    "password": "hunter2",
                    "vdom": "root",
                },
            }
        }
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


@pytest.fixture
def db_url(tmp_path):
    # file-based (not :memory:) so a fresh engine/session in assertions
    # below sees the same data the migration just committed.
    return f"sqlite+aiosqlite:///{(tmp_path / 'inventory.db').as_posix()}"


class TestMigrateConfig:
    @pytest.mark.asyncio
    async def test_migrates_token_and_basic_auth_devices(self, legacy_config_file, db_url):
        created_ids = await migration.migrate_config(legacy_config_file, database_url=db_url)

        assert len(created_ids) == 2

        engine = real_create_engine(db_url)
        session_factory = create_session_factory(engine)
        credentials = CredentialManager()
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            devices = await inventory.list_devices()
            by_name = {d.name: d for d in devices}

            assert by_name["default"].mgmt_host == "192.168.1.1"
            assert by_name["default"].verify_ssl is False
            assert credentials.resolve(by_name["default"].credential_id) == {
                "auth_type": "token",
                "api_token": "legacy-token-1",
            }

            assert by_name["backup"].mgmt_host == "192.168.1.2"
            assert credentials.resolve(by_name["backup"].credential_id) == {
                "auth_type": "basic",
                "username": "admin",
                "password": "hunter2",
            }
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_devices_land_under_legacy_customer_and_default_site(
        self, legacy_config_file, db_url
    ):
        await migration.migrate_config(legacy_config_file, database_url=db_url)

        engine = real_create_engine(db_url)
        session_factory = create_session_factory(engine)
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            customers = await inventory.list_customers()
            assert [c.name for c in customers] == [migration.DEFAULT_CUSTOMER]
            sites = await inventory.list_sites(customers[0].id)
            assert [s.name for s in sites] == [migration.DEFAULT_SITE]
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_rerunning_migration_does_not_duplicate_devices(self, legacy_config_file, db_url):
        first_created = await migration.migrate_config(legacy_config_file, database_url=db_url)
        second_created = await migration.migrate_config(legacy_config_file, database_url=db_url)

        assert len(first_created) == 2
        assert second_created == []  # nothing new the second time

        engine = real_create_engine(db_url)
        session_factory = create_session_factory(engine)
        async with session_factory() as session:
            inventory = InventoryRepository(session)
            devices = await inventory.list_devices()
            assert len(devices) == 2  # still exactly two, not four
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_empty_devices_section_returns_empty_list(self, tmp_path, db_url):
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"fortigate": {"devices": {}}}), encoding="utf-8")

        created = await migration.migrate_config(path, database_url=db_url)

        assert created == []


class TestMigrationCli:
    def test_main_reports_error_for_missing_config(self, tmp_path, capsys):
        missing = tmp_path / "does_not_exist.json"

        exit_code = migration.main(["--config", str(missing)])

        assert exit_code == 1
        assert "not found" in capsys.readouterr().err

    def test_main_migrates_and_prints_summary(self, legacy_config_file, db_url, monkeypatch, capsys):
        monkeypatch.setattr(
            migration, "create_engine", lambda url=None: real_create_engine(db_url)
        )

        exit_code = migration.main(["--config", str(legacy_config_file)])

        assert exit_code == 0
        out = capsys.readouterr().out
        assert "Migrated 2 new device(s)" in out
