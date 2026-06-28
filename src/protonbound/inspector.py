"""Developer inspection CLI.

Mirrors the exact tool interface and data payloads that the MCP server sends to the LLM,
so developers can audit what the AI actually sees — fencing tags, opaque tokens,
thread-folded and de-duplicated bodies, and prompt-injection defanging — without routing
real email through a live AI agent.

Usage (one-shot, args passed via --inspect):
    protonbound --workspace w.yaml --inspect info
    protonbound --workspace w.yaml --inspect folders
    protonbound --workspace w.yaml --inspect threads
    protonbound --workspace w.yaml --inspect threads --limit 10
    protonbound --workspace w.yaml --inspect search "invoice"
    protonbound --workspace w.yaml --inspect search --from sender@example.com --days 7
    protonbound --workspace w.yaml --inspect thread <thread_id>
    protonbound --workspace w.yaml --inspect message <message_id>
    protonbound --workspace w.yaml --inspect status
    protonbound --workspace w.yaml --inspect --raw search "query"   # bare JSON, pipeable

Usage (interactive REPL):
    protonbound --workspace w.yaml --inspect
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from typing import Any

from .config import Workspace
from .mail import ProtonMailClient
from .server import _password_provider

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

def _ansi(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _bold(t: str) -> str:  return _ansi("1",    t)
def _dim(t: str)  -> str:  return _ansi("2",    t)
def _cyan(t: str) -> str:  return _ansi("36",   t)
def _green(t: str)-> str:  return _ansi("32",   t)
def _red(t: str)  -> str:  return _ansi("31",   t)
def _yellow(t: str)-> str: return _ansi("33",   t)


def _hr() -> str:
    return _dim("─" * 72)


def _err(msg: str) -> None:
    print(_red(f"✗  {msg}"), file=sys.stderr)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _emit(label: str, data: Any, *, raw: bool) -> None:
    """Print a tool result exactly as the LLM would receive it (JSON wire format)."""
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    if raw:
        print(payload)
        return
    print(_hr())
    print(_bold(f"  tool result: {label}"))
    print(_hr())
    print(payload)
    print()


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def _make_client(workspace: Workspace) -> ProtonMailClient:
    return ProtonMailClient(
        account=workspace.meta.account,
        mail=workspace.mail,
        password_provider=_password_provider(workspace.meta.account),
    )


# ---------------------------------------------------------------------------
# Command implementations — each replicates the exact server tool call
# ---------------------------------------------------------------------------

_HELP = """\
Commands  (same interface the MCP server exposes to the LLM)
─────────────────────────────────────────────────────────────
  info                             get_workspace_info
  folders                          list_folders
  threads [--limit N]              list_threads  (default limit 50)
  thread  <thread_id>              get_thread     — folded, de-duped bodies
  message <message_id>             get_message    — full un-folded body
  search  [QUERY] [options]        search_mail
    --from ADDR                      filter by sender address
    --to   ADDR                      filter by recipient / BCC
    --days N                         only mail within the last N days
    --unread                         only unread messages
    --body                           include body in search (slower)
  status                           connection + session token stats
  help / ?                         this message
  quit / exit / q                  exit the REPL
─────────────────────────────────────────────────────────────
Tip: bodies arrive fenced in <untrusted-email-content> exactly as the LLM sees them.
     Any attempt by a body to forge the closing tag is defanged to &lt;/untrusted…&gt;.
"""


def _cmd_info(workspace: Workspace, _rest: list[str], *, raw: bool) -> None:
    mail = workspace.mail
    scope = mail.scope
    data = {
        "name": workspace.meta.name,
        "description": workspace.meta.description,
        "permission": mail.permission.value,
        "can_write_drafts": mail.can_write,
        "can_send": mail.allow_smtp,
        "scope": {
            "sources": scope.sources,
            "require_starred": scope.require_starred,
            "addresses": scope.addresses or "(any within sources)",
        },
        "delete_enabled": mail.allow_delete,
        "local_attachments_enabled": mail.allow_local_attachments,
        "max_attachment_mb": mail.max_attachment_mb,
        "bridge_cert_pinned": bool(workspace.meta.account.bridge_cert_sha256),
        "tools_allowlist": mail.tools,
    }
    _emit("get_workspace_info", data, raw=raw)


def _cmd_folders(client: ProtonMailClient, _rest: list[str], *, raw: bool) -> None:
    data = client.list_folders()
    _emit("list_folders", data, raw=raw)


def _cmd_threads(client: ProtonMailClient, rest: list[str], *, raw: bool) -> None:
    p = argparse.ArgumentParser(prog="threads", add_help=False)
    p.add_argument("--limit", type=int, default=50)
    ns, _ = p.parse_known_args(rest)
    data = client.list_threads(limit=ns.limit)
    _emit(f"list_threads(limit={ns.limit})  [{len(data)} thread(s)]", data, raw=raw)


def _cmd_thread(client: ProtonMailClient, rest: list[str], *, raw: bool) -> None:
    if not rest:
        _err("usage: thread <thread_id>")
        return
    tid = rest[0]
    data = client.get_thread(tid)
    _emit(f"get_thread({tid!r})", data, raw=raw)


def _cmd_message(client: ProtonMailClient, rest: list[str], *, raw: bool) -> None:
    if not rest:
        _err("usage: message <message_id>")
        return
    mid = rest[0]
    data = client.get_message(mid)
    _emit(f"get_message({mid!r})", data, raw=raw)


def _cmd_search(client: ProtonMailClient, rest: list[str], *, raw: bool) -> None:
    p = argparse.ArgumentParser(prog="search", add_help=False)
    p.add_argument("query", nargs="?", default="")
    p.add_argument("--from", dest="from_addr", default=None)
    p.add_argument("--to",   dest="to_addr",   default=None)
    p.add_argument("--days", dest="since_days", type=int, default=None)
    p.add_argument("--unread", dest="unread_only", action="store_true")
    p.add_argument("--body",   dest="include_body", action="store_true")
    ns, _ = p.parse_known_args(rest)

    data = client.search_mail(
        ns.query,
        from_addr=ns.from_addr,
        to_addr=ns.to_addr,
        since_days=ns.since_days,
        unread_only=ns.unread_only,
        include_body=ns.include_body,
    )

    parts = [f"query={ns.query!r}"]
    if ns.from_addr:
        parts.append(f"from_addr={ns.from_addr!r}")
    if ns.to_addr:
        parts.append(f"to_addr={ns.to_addr!r}")
    if ns.since_days:
        parts.append(f"since_days={ns.since_days}")
    if ns.unread_only:
        parts.append("unread_only=True")
    if ns.include_body:
        parts.append("include_body=True")
    _emit(f"search_mail({', '.join(parts)})  [{len(data)} result(s)]", data, raw=raw)


def _cmd_status(client: ProtonMailClient, workspace: Workspace, *, raw: bool) -> None:
    conn = getattr(client, "_conn", None)
    last_active = getattr(client, "_last_active", None)
    idle_s: float | None = None
    if conn is not None and last_active is not None:
        idle_s = round(time.monotonic() - last_active, 2)

    issued_ids: set = getattr(client, "_issued_ids", set())
    acc = workspace.meta.account

    data = {
        "workspace": workspace.meta.name,
        "imap_endpoint": f"{acc.imap_host}:{acc.imap_port}",
        "connection": {
            "established": conn is not None,
            "idle_seconds": idle_s,
            "probe_after_idle_seconds": 30.0,
            "will_probe_on_next_call": (
                idle_s is not None and idle_s >= 30.0
            ),
        },
        "session": {
            "issued_token_count": len(issued_ids),
            "description": (
                "Opaque tokens handed to the LLM so far in this session. "
                "A by-id call presenting an unknown token is rejected before "
                "any IMAP command runs."
            ),
        },
        "tls": {
            "cert_pinned": bool(acc.bridge_cert_sha256),
            "fingerprint_prefix": (
                acc.bridge_cert_sha256[:16] + "…"
                if acc.bridge_cert_sha256
                else None
            ),
        },
    }
    _emit("status", data, raw=raw)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _dispatch(
    tokens: list[str],
    client: ProtonMailClient,
    workspace: Workspace,
    *,
    raw: bool,
) -> bool:
    """Run one parsed command. Returns False to signal REPL exit."""
    if not tokens:
        return True

    # Strip a leading --raw flag that the REPL might receive inline
    if "--raw" in tokens:
        raw = True
        tokens = [t for t in tokens if t != "--raw"]
    if not tokens:
        return True

    cmd, *rest = tokens
    cmd = cmd.lower()

    if cmd in ("quit", "exit", "q"):
        return False

    if cmd in ("help", "?", "h"):
        print(_HELP)
        return True

    if cmd == "info":
        _cmd_info(workspace, rest, raw=raw)
    elif cmd == "folders":
        _cmd_folders(client, rest, raw=raw)
    elif cmd == "threads":
        _cmd_threads(client, rest, raw=raw)
    elif cmd == "thread":
        _cmd_thread(client, rest, raw=raw)
    elif cmd == "message":
        _cmd_message(client, rest, raw=raw)
    elif cmd == "search":
        _cmd_search(client, rest, raw=raw)
    elif cmd == "status":
        _cmd_status(client, workspace, raw=raw)
    else:
        _err(f"Unknown command {cmd!r}. Type 'help' for the command list.")

    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_inspect(workspace: Workspace, args: list[str]) -> int:
    """Called from __main__.main() when --inspect is present.

    ``args`` is everything after ``--inspect`` on the command line.
    Empty list → interactive REPL; non-empty → one-shot command.
    """

    raw = "--raw" in args
    if raw:
        args = [a for a in args if a != "--raw"]

    client = _make_client(workspace)

    # ── One-shot mode ────────────────────────────────────────────────────────
    if args:
        try:
            _dispatch(args, client, workspace, raw=raw)
        except Exception as exc:  # noqa: BLE001
            _err(str(exc))
            return 1
        return 0

    # ── Interactive REPL ─────────────────────────────────────────────────────
    try:
        import readline as _rl  # noqa: F401 — enables history and line editing
        _rl.parse_and_bind("tab: complete")
    except ImportError:
        # readline is stdlib but absent on a stock Windows Python (it's POSIX-only). It is a
        # pure convenience here, so degrade silently to a plain input() REPL rather than fail.
        pass

    banner = (
        _bold("ProtonBound Inspector")
        + _dim("  —  showing the exact payloads the LLM receives")
    )
    scope_line = _dim(
        f"workspace: {workspace.meta.name}"
        f"  |  sources: {', '.join(workspace.mail.scope.sources)}"
    )
    print(banner)
    print(scope_line)
    print(_dim("Type 'help' for commands, 'quit' to exit, '--raw' before any command for bare JSON."))
    print()

    while True:
        try:
            line = input(_cyan("inspect> "))
        except (EOFError, KeyboardInterrupt):
            print()
            break

        line = line.strip()
        if not line:
            continue

        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            _err(f"parse error: {exc}")
            continue

        try:
            if not _dispatch(tokens, client, workspace, raw=raw):
                break
        except Exception as exc:  # noqa: BLE001
            _err(str(exc))

    return 0
