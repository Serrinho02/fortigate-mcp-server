"""
CredentialManager -- the only module in the codebase allowed to import
`keyring`. Everything else refers to credentials by opaque `credential_id`
only (see architecture plan §7).

Secrets are decoded from the OS-native store (Windows Credential Manager /
macOS Keychain / Linux Secret Service, via `keyring`) at connection time
only, in `ConnectionManager.get_session`, and the reference is dropped
immediately after building the adapter's auth header/session -- nothing
in the Service/Domain/Repository layers ever holds a secret field.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Literal, Optional

import keyring
import keyring.errors

_SERVICE_PREFIX = "fortinet-mcp"
_SECRET_USERNAME = "secret"  # fixed placeholder; the real username (if any) lives inside the JSON blob


class CredentialManager:
    @staticmethod
    def generate_credential_id() -> str:
        return f"cred_{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _service_name(credential_id: str) -> str:
        return f"{_SERVICE_PREFIX}:{credential_id}"

    def set_secret(
        self,
        credential_id: str,
        *,
        auth_type: Literal["token", "basic"],
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """Store a secret blob for `credential_id`. Human/CLI-only in practice
        (see cli/cred.py) -- never called from an MCP tool handler."""
        if auth_type == "token":
            if not api_token:
                raise ValueError("api_token is required when auth_type='token'")
            blob: dict[str, Any] = {"auth_type": "token", "api_token": api_token}
        elif auth_type == "basic":
            if not username or not password:
                raise ValueError("username and password are required when auth_type='basic'")
            blob = {"auth_type": "basic", "username": username, "password": password}
        else:
            raise ValueError(f"Unknown auth_type: {auth_type!r}")

        keyring.set_password(self._service_name(credential_id), _SECRET_USERNAME, json.dumps(blob))

    def resolve(self, credential_id: str) -> Optional[dict[str, Any]]:
        """Decode the stored blob for `credential_id`, or None if not provisioned."""
        raw = keyring.get_password(self._service_name(credential_id), _SECRET_USERNAME)
        if raw is None:
            return None
        return json.loads(raw)

    def is_provisioned(self, credential_id: str) -> bool:
        return keyring.get_password(self._service_name(credential_id), _SECRET_USERNAME) is not None

    def delete(self, credential_id: str) -> None:
        try:
            keyring.delete_password(self._service_name(credential_id), _SECRET_USERNAME)
        except keyring.errors.PasswordDeleteError:
            pass  # already absent -- deleting a non-existent credential is a no-op
