"""CLI entry point: ``protonbound --workspace <file>``.

Each server instance is bound to exactly one workspace YAML file, selected here at launch
(via the ``--workspace`` flag or the ``PROTONBOUND_WORKSPACE`` environment variable). The
agent therefore cannot reference any other workspace — isolation is structural.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from .config import load_workspace
from .server import KEYRING_SERVICE, build_server


def _set_password(workspace) -> int:
    """Prompt for the Bridge password and store it in the OS keyring for this workspace's
    IMAP username, so the secret never lives in an env var or config file."""

    try:
        import keyring
    except Exception:  # noqa: BLE001
        print(
            "protonbound: the 'keyring' package is required for --set-password "
            "(pip install keyring).",
            file=sys.stderr,
        )
        return 2
    username = workspace.meta.account.username
    secret = getpass.getpass(f"Bridge password for {username}: ")
    if not secret:
        print("protonbound: no password entered; nothing stored.", file=sys.stderr)
        return 2
    keyring.set_password(KEYRING_SERVICE, username, secret)
    print(f"Stored Bridge password for {username} in the OS keyring.")
    return 0


def _show_cert(workspace) -> int:
    """Print Bridge's TLS cert SHA-256 so the user can pin it via account.bridge_cert_sha256."""

    from .mail import ProtonMailClient
    from .server import _password_provider

    client = ProtonMailClient(
        account=workspace.meta.account,
        mail=workspace.mail,
        password_provider=_password_provider(workspace.meta.account),
    )
    try:
        fingerprint = client.bridge_cert_fingerprint()
    except Exception as exc:  # noqa: BLE001
        print(f"protonbound: {exc}", file=sys.stderr)
        return 2
    print(f"Bridge TLS cert SHA-256: {fingerprint}")
    print('Pin it by adding under "account:" in the workspace file:')
    print(f'  bridge_cert_sha256: "{fingerprint}"')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="protonbound",
        description="Scoped, draft-only MCP server for Proton Mail via Proton Bridge.",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("PROTONBOUND_WORKSPACE"),
        help="Path to the workspace YAML file (or set PROTONBOUND_WORKSPACE).",
    )
    parser.add_argument(
        "--set-password",
        action="store_true",
        help="Store this workspace's Bridge password in the OS keyring, then exit.",
    )
    parser.add_argument(
        "--show-cert",
        action="store_true",
        help="Print Proton Bridge's TLS cert SHA-256 fingerprint (for pinning), then exit.",
    )
    parser.add_argument(
        "--inspect",
        nargs=argparse.REMAINDER,
        metavar="CMD [ARGS...]",
        help=(
            "Launch the developer inspection CLI instead of the MCP server. "
            "Shows the exact tool payloads the LLM receives, including "
            "<untrusted-email-content> fencing and opaque message tokens. "
            "Omit CMD for an interactive REPL; add --raw for bare JSON output. "
            "Example: --inspect search 'invoice'  or  --inspect threads --limit 5"
        ),
    )
    args = parser.parse_args(argv)

    if not args.workspace:
        parser.error("a workspace is required (--workspace or PROTONBOUND_WORKSPACE)")

    try:
        workspace = load_workspace(args.workspace)
    except Exception as exc:  # noqa: BLE001 - surface a clean message, not a traceback
        print(f"protonbound: failed to load workspace: {exc}", file=sys.stderr)
        return 2

    if args.set_password:
        return _set_password(workspace)

    if args.show_cert:
        return _show_cert(workspace)

    if args.inspect is not None:
        from .inspector import run_inspect
        return run_inspect(workspace, list(args.inspect))

    server = build_server(workspace)
    server.run()  # stdio transport by default
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
