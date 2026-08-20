"""
Tests for the cli/cred.py human-only secret provisioning tool.
`keyring` is monkeypatched to the same in-memory fake used by
test_fortinet_credential_manager.py -- never touches the real OS store.
"""
import keyring
import pytest

from src.fortinet_mcp.cli import cred as cred_cli
from src.fortinet_mcp.infra.credential_manager import CredentialManager
from tests.test_fortinet_credential_manager import FakeKeyring


@pytest.fixture(autouse=True)
def fake_keyring_backend():
    original = keyring.get_keyring()
    keyring.set_keyring(FakeKeyring())
    yield
    keyring.set_keyring(original)


@pytest.fixture
def manager():
    return CredentialManager()


class TestBuildParser:
    def test_set_requires_auth_type(self):
        parser = cred_cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["set", "cred_abc"])

    def test_set_parses_token_auth_type(self):
        parser = cred_cli.build_parser()
        args = parser.parse_args(["set", "cred_abc", "--auth-type", "token"])
        assert args.credential_id == "cred_abc"
        assert args.auth_type == "token"
        assert args.command == "set"

    def test_status_parses(self):
        parser = cred_cli.build_parser()
        args = parser.parse_args(["status", "cred_abc"])
        assert args.credential_id == "cred_abc"

    def test_delete_defaults_yes_to_false(self):
        parser = cred_cli.build_parser()
        args = parser.parse_args(["delete", "cred_abc"])
        assert args.yes is False


class TestCmdSetTokenFlow:
    def test_set_token_stores_secret(self, monkeypatch, manager, capsys):
        monkeypatch.setattr(cred_cli.getpass, "getpass", lambda prompt="": "my-api-token")

        exit_code = cred_cli.main(["set", "cred_abc", "--auth-type", "token"])

        assert exit_code == 0
        assert manager.resolve("cred_abc") == {"auth_type": "token", "api_token": "my-api-token"}
        assert "stored" in capsys.readouterr().out

    def test_set_token_empty_value_fails(self, monkeypatch, manager):
        monkeypatch.setattr(cred_cli.getpass, "getpass", lambda prompt="": "")

        exit_code = cred_cli.main(["set", "cred_abc", "--auth-type", "token"])

        assert exit_code == 1
        assert manager.resolve("cred_abc") is None


class TestCmdSetBasicFlow:
    def test_set_basic_stores_secret(self, monkeypatch, manager):
        monkeypatch.setattr("builtins.input", lambda prompt="": "admin")
        monkeypatch.setattr(cred_cli.getpass, "getpass", lambda prompt="": "hunter2")

        exit_code = cred_cli.main(["set", "cred_xyz", "--auth-type", "basic"])

        assert exit_code == 0
        assert manager.resolve("cred_xyz") == {
            "auth_type": "basic",
            "username": "admin",
            "password": "hunter2",
        }


class TestCmdStatus:
    def test_status_reports_not_provisioned(self, capsys):
        exit_code = cred_cli.main(["status", "cred_never"])
        assert exit_code == 0
        assert "NOT provisioned" in capsys.readouterr().out

    def test_status_reports_provisioned(self, manager, capsys):
        manager.set_secret("cred_abc", auth_type="token", api_token="x")

        exit_code = cred_cli.main(["status", "cred_abc"])

        assert exit_code == 0
        out = capsys.readouterr().out
        assert "provisioned" in out
        assert "NOT provisioned" not in out


class TestCmdDelete:
    def test_delete_with_yes_flag_skips_confirmation(self, manager):
        manager.set_secret("cred_abc", auth_type="token", api_token="x")

        exit_code = cred_cli.main(["delete", "cred_abc", "--yes"])

        assert exit_code == 0
        assert manager.resolve("cred_abc") is None

    def test_delete_aborted_when_not_confirmed(self, monkeypatch, manager):
        manager.set_secret("cred_abc", auth_type="token", api_token="x")
        monkeypatch.setattr("builtins.input", lambda prompt="": "n")

        exit_code = cred_cli.main(["delete", "cred_abc"])

        assert exit_code == 1
        assert manager.resolve("cred_abc") == {"auth_type": "token", "api_token": "x"}
