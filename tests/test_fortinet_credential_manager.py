"""
Tests for CredentialManager. `keyring` is monkeypatched to an in-memory
fake backend for every test in this file -- these tests must never touch
the real OS credential store (Windows Credential Manager / Keychain /
Secret Service).
"""
import keyring
import keyring.errors
import pytest

from src.fortinet_mcp.infra.credential_manager import CredentialManager


class FakeKeyring(keyring.backend.KeyringBackend):
    """Minimal in-memory keyring backend for hermetic tests."""

    priority = 1  # required by KeyringBackend, arbitrary here

    def __init__(self):
        self._store: dict[tuple[str, str], str] = {}

    def set_password(self, service, username, password):
        self._store[(service, username)] = password

    def get_password(self, service, username):
        return self._store.get((service, username))

    def delete_password(self, service, username):
        key = (service, username)
        if key not in self._store:
            raise keyring.errors.PasswordDeleteError("not found")
        del self._store[key]


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


@pytest.fixture
def manager():
    return CredentialManager()


class TestCredentialManagerTokenAuth:
    def test_set_and_resolve_token_secret(self, manager):
        cred_id = manager.generate_credential_id()
        manager.set_secret(cred_id, auth_type="token", api_token="s3cr3t-token")

        resolved = manager.resolve(cred_id)

        assert resolved == {"auth_type": "token", "api_token": "s3cr3t-token"}

    def test_set_token_without_value_raises(self, manager):
        with pytest.raises(ValueError):
            manager.set_secret(manager.generate_credential_id(), auth_type="token")


class TestCredentialManagerBasicAuth:
    def test_set_and_resolve_basic_secret(self, manager):
        cred_id = manager.generate_credential_id()
        manager.set_secret(cred_id, auth_type="basic", username="admin", password="hunter2")

        resolved = manager.resolve(cred_id)

        assert resolved == {"auth_type": "basic", "username": "admin", "password": "hunter2"}

    def test_set_basic_missing_username_raises(self, manager):
        with pytest.raises(ValueError):
            manager.set_secret(manager.generate_credential_id(), auth_type="basic", password="x")

    def test_set_basic_missing_password_raises(self, manager):
        with pytest.raises(ValueError):
            manager.set_secret(manager.generate_credential_id(), auth_type="basic", username="admin")


class TestCredentialManagerLifecycle:
    def test_unknown_auth_type_raises(self, manager):
        with pytest.raises(ValueError):
            manager.set_secret(manager.generate_credential_id(), auth_type="oauth")  # type: ignore[arg-type]

    def test_resolve_unprovisioned_credential_returns_none(self, manager):
        assert manager.resolve("cred_neverset") is None

    def test_is_provisioned_reflects_state(self, manager):
        cred_id = manager.generate_credential_id()
        assert manager.is_provisioned(cred_id) is False

        manager.set_secret(cred_id, auth_type="token", api_token="abc")
        assert manager.is_provisioned(cred_id) is True

    def test_delete_removes_secret(self, manager):
        cred_id = manager.generate_credential_id()
        manager.set_secret(cred_id, auth_type="token", api_token="abc")

        manager.delete(cred_id)

        assert manager.is_provisioned(cred_id) is False

    def test_delete_nonexistent_credential_is_a_no_op(self, manager):
        manager.delete("cred_neverexisted")  # must not raise

    def test_generated_credential_ids_are_unique(self, manager):
        ids = {manager.generate_credential_id() for _ in range(100)}
        assert len(ids) == 100

    def test_two_credential_ids_do_not_collide_in_storage(self, manager):
        cred_a = manager.generate_credential_id()
        cred_b = manager.generate_credential_id()
        manager.set_secret(cred_a, auth_type="token", api_token="token-a")
        manager.set_secret(cred_b, auth_type="token", api_token="token-b")

        assert manager.resolve(cred_a) == {"auth_type": "token", "api_token": "token-a"}
        assert manager.resolve(cred_b) == {"auth_type": "token", "api_token": "token-b"}
