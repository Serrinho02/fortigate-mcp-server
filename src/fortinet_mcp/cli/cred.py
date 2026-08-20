"""
fortinet-mcp-cred -- the only channel through which a real secret enters
this system.

Deliberately outside the MCP tool surface: no LLM, no chat transcript, no
tool-call argument ever carries a password or API token. A device created
via the `inventory.register_device_pending` MCP tool gets a freshly minted
`credential_id` but stays unusable until a human runs this CLI.

Usage:
    python -m src.fortinet_mcp.cli.cred set <credential_id> --auth-type token
    python -m src.fortinet_mcp.cli.cred set <credential_id> --auth-type basic
    python -m src.fortinet_mcp.cli.cred status <credential_id>
    python -m src.fortinet_mcp.cli.cred delete <credential_id>
"""
from __future__ import annotations

import argparse
import getpass
import sys
from typing import Optional, Sequence

from ..infra.credential_manager import CredentialManager


def _cmd_set(args: argparse.Namespace, manager: CredentialManager) -> int:
    if args.auth_type == "token":
        api_token = getpass.getpass("API token: ")
        if not api_token:
            print("error: API token must not be empty", file=sys.stderr)
            return 1
        manager.set_secret(args.credential_id, auth_type="token", api_token=api_token)
    else:
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        if not username or not password:
            print("error: username and password must not be empty", file=sys.stderr)
            return 1
        manager.set_secret(
            args.credential_id, auth_type="basic", username=username, password=password
        )

    print(f"Credential '{args.credential_id}' stored in the OS credential store.")
    return 0


def _cmd_status(args: argparse.Namespace, manager: CredentialManager) -> int:
    if manager.is_provisioned(args.credential_id):
        print(f"Credential '{args.credential_id}': provisioned")
    else:
        print(f"Credential '{args.credential_id}': NOT provisioned")
    return 0


def _cmd_delete(args: argparse.Namespace, manager: CredentialManager) -> int:
    if not args.yes:
        confirm = input(f"Delete credential '{args.credential_id}'? [y/N] ")
        if confirm.strip().lower() != "y":
            print("Aborted.")
            return 1
    manager.delete(args.credential_id)
    print(f"Credential '{args.credential_id}' deleted.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fortinet-mcp-cred",
        description=(
            "Provision FortiGate/Fortinet device credentials into the OS credential "
            "store. This is the only place a real secret is ever typed -- Claude "
            "never sees it."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    set_parser = subparsers.add_parser("set", help="Store a secret for a credential_id")
    set_parser.add_argument("credential_id")
    set_parser.add_argument("--auth-type", choices=["token", "basic"], required=True)
    set_parser.set_defaults(func=_cmd_set)

    status_parser = subparsers.add_parser(
        "status", help="Check whether a credential_id is provisioned (never shows the secret)"
    )
    status_parser.add_argument("credential_id")
    status_parser.set_defaults(func=_cmd_status)

    delete_parser = subparsers.add_parser("delete", help="Remove a stored secret")
    delete_parser.add_argument("credential_id")
    delete_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    delete_parser.set_defaults(func=_cmd_delete)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    manager = CredentialManager()
    return args.func(args, manager)


if __name__ == "__main__":
    raise SystemExit(main())
