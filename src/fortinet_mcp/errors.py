"""
Shared exception types used across the inventory/connection stack.

Kept in one place (rather than one exception module per layer) because
callers up in the MCP tool layer need to catch these regardless of which
component raised them.
"""
from __future__ import annotations


class FortinetMcpError(Exception):
    """Base class for all fortinet_mcp platform errors."""


class DuplicateNameError(FortinetMcpError):
    """A Customer/Site/Device with that name already exists in its scope."""


class DeviceNotFoundError(FortinetMcpError):
    """No device matched the given target string."""

    def __init__(self, target: str):
        super().__init__(f"No device found matching '{target}'")
        self.target = target


class AmbiguousTargetError(FortinetMcpError):
    """More than one device matched the given target string.

    The caller (Service/MCP tool layer) is expected to surface `candidates`
    back to Claude for disambiguation rather than guessing.
    """

    def __init__(self, target: str, candidates: list[str]):
        super().__init__(
            f"'{target}' matches multiple devices: {', '.join(candidates)}. "
            "Please specify one explicitly."
        )
        self.target = target
        self.candidates = candidates


class DeviceConnectionError(FortinetMcpError):
    """The adapter's health probe failed when establishing a new session."""

    def __init__(self, device_name: str, mgmt_host: str):
        super().__init__(f"Unable to connect to device '{device_name}' ({mgmt_host})")
        self.device_name = device_name
        self.mgmt_host = mgmt_host


class CredentialNotProvisionedError(FortinetMcpError):
    """A device references a credential_id with no secret stored in the keyring yet."""

    def __init__(self, credential_id: str):
        super().__init__(
            f"Credential '{credential_id}' has not been provisioned yet. "
            f"Run: fortinet-mcp-cred set {credential_id}"
        )
        self.credential_id = credential_id


class ModeViolationError(FortinetMcpError):
    """The server's current operating mode (READ_ONLY/SAFE) forbids this operation."""


class ChangeNotFoundError(FortinetMcpError):
    """No ChangeRecord matches the given change_id."""

    def __init__(self, change_id: str):
        super().__init__(f"No change found with id '{change_id}'")
        self.change_id = change_id


class ChangeAlreadyResolvedError(FortinetMcpError):
    """change.apply/change.rollback called on a ChangeRecord that isn't in the expected status."""

    def __init__(self, change_id: str, status: str):
        super().__init__(f"Change '{change_id}' is already {status}")
        self.change_id = change_id
        self.status = status


class ChangeExpiredError(FortinetMcpError):
    """The change's preview TTL elapsed before change.apply was called."""

    def __init__(self, change_id: str):
        super().__init__(
            f"Change '{change_id}' has expired. Run the operation again to get a fresh preview."
        )
        self.change_id = change_id


class ChangeDriftError(FortinetMcpError):
    """The live resource state no longer matches what was diffed at preview time."""

    def __init__(self, change_id: str):
        super().__init__(
            f"The live state has changed since change '{change_id}' was previewed. "
            "Run the operation again to get a fresh preview before applying."
        )
        self.change_id = change_id


class RollbackNotPossibleError(FortinetMcpError):
    """The applied change can't be automatically rolled back (e.g. FortiOS's create
    response didn't include an identifiable key for the resource that was created)."""

    def __init__(self, change_id: str, reason: str):
        super().__init__(f"Cannot roll back change '{change_id}': {reason}")
        self.change_id = change_id
        self.reason = reason
