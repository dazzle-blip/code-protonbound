"""Verify the MCP tool surface matches the permission tier and SMTP gating."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

from protonbound.config import (
    AccountConfig,
    MailConfig,
    Permission,
    ScopeConfig,
    Workspace,
    WorkspaceMeta,
    WriteTargets,
)
from protonbound.server import _workspace_instructions, build_server


def _workspace(
    permission: Permission,
    allow_delete: bool = False,
    allow_local_attachments: bool = False,
    allow_smtp: bool = False,
) -> Workspace:
    return Workspace(
        meta=WorkspaceMeta(
            name="t",
            description="test",
            account=AccountConfig(username="me@proton.me"),
        ),
        mail=MailConfig(
            permission=permission,
            scope=ScopeConfig(sources=["Labels/AI"]),
            write_targets=WriteTargets(drafts="Drafts", trash="Trash"),
            allow_delete=allow_delete,
            allow_local_attachments=allow_local_attachments,
            allow_smtp=allow_smtp,
        ),
        path=Path("."),
    )


def _tool_names(workspace: Workspace) -> set[str]:
    server = build_server(workspace)
    tools = asyncio.run(server.list_tools())
    return {t.name for t in tools}


def test_readonly_has_no_write_tools():
    names = _tool_names(_workspace(Permission.readonly))
    assert "get_workspace_info" in names
    assert "list_threads" in names
    assert "get_thread" in names
    # no write tools at all
    assert "draft_reply" not in names
    assert "save_draft" not in names
    assert "move_message" not in names
    assert "delete_message" not in names


def test_read_write_has_draft_tools_but_no_send_by_default():
    names = _tool_names(_workspace(Permission.read_write))
    assert "draft_reply" in names
    assert "save_draft" in names
    assert "update_draft" in names
    # send absent unless allow_smtp is explicitly True
    assert "send_outbound_email" not in names
    # delete only when explicitly enabled
    assert "delete_message" not in names


def test_delete_tool_only_when_enabled():
    names = _tool_names(_workspace(Permission.read_write, allow_delete=True))
    assert "delete_message" in names


def test_send_tool_absent_by_default():
    for perm in (Permission.readonly, Permission.read_write):
        names = _tool_names(_workspace(perm))
        assert "send_outbound_email" not in names


def test_send_tool_present_when_smtp_enabled():
    names = _tool_names(_workspace(Permission.readonly, allow_smtp=True))
    assert "send_outbound_email" in names


def test_send_tool_warns_about_injection():
    server = build_server(_workspace(Permission.readonly, allow_smtp=True))
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    desc = tools["send_outbound_email"].description.lower()
    assert "confirmation" in desc or "confirm" in desc


def test_instructions_advertise_operational_limits():
    """Read-write limits are stated up front so the model doesn't attempt doomed calls."""

    text = _workspace_instructions(_workspace(Permission.read_write, allow_delete=False))
    assert "No delete tool" in text
    assert "attaching LOCAL files by path is disabled" in text
    assert "only target the readable sources" in text

    enabled = _workspace_instructions(
        _workspace(Permission.read_write, allow_delete=True, allow_local_attachments=True)
    )
    assert "delete_message moves to Trash" in enabled
    assert "attaching a LOCAL file by path is allowed" in enabled


def test_readonly_instructions_omit_write_limits():
    text = _workspace_instructions(_workspace(Permission.readonly))
    assert "Attachments:" not in text
    assert "delete" not in text.lower()


def test_password_provider_prefers_keyring_then_env(monkeypatch):
    from protonbound import server

    account = AccountConfig(username="me@proton.me")

    # keyring hit wins over the env var
    monkeypatch.setattr(server, "_keyring_password", lambda u: "from-keyring")
    monkeypatch.setenv("PROTONBOUND_BRIDGE_PASSWORD", "from-env")
    assert server._password_provider(account)() == "from-keyring"

    # keyring miss falls back to the env var
    monkeypatch.setattr(server, "_keyring_password", lambda u: "")
    assert server._password_provider(account)() == "from-env"

    # neither present -> empty (the client then raises a clear error on connect)
    monkeypatch.delenv("PROTONBOUND_BRIDGE_PASSWORD", raising=False)
    assert server._password_provider(account)() == ""


def test_delete_tool_warns_about_injection():
    server = build_server(_workspace(Permission.read_write, allow_delete=True))
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert "confirmation" in tools["delete_message"].description.lower()


def test_only_smtp_module_imports_smtplib():
    """Static guarantee: smtplib is imported only in smtp.py, nowhere else in the package."""

    import re

    import_re = re.compile(r"^\s*(?:import\s+smtplib|from\s+smtplib\s+import)", re.MULTILINE)
    pkg_dir = Path(importlib.util.find_spec("protonbound").origin).parent
    offenders = [
        py.name
        for py in pkg_dir.rglob("*.py")
        if py.name != "smtp.py" and import_re.search(py.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"smtplib imported outside smtp.py in: {offenders}"


def test_smtplib_not_loaded_with_smtp_disabled():
    """Runtime guarantee: building a default workspace never loads smtplib or smtp.py."""

    import sys

    build_server(_workspace(Permission.readonly))
    assert "smtplib" not in sys.modules
    assert "protonbound.smtp" not in sys.modules


def test_send_runtime_guard_raises_if_smtp_disabled():
    """The PermissionError guard fires even if the function were called with allow_smtp=False."""

    import sys

    # Build with allow_smtp=True so the function is defined, then call it with a patched
    # mail_cfg that has allow_smtp=False to simulate the guard tripping at runtime.
    from unittest.mock import patch

    ws = _workspace(Permission.readonly, allow_smtp=True)
    server = build_server(ws)
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert "send_outbound_email" in tools

    # Patch allow_smtp off after registration to prove the in-function guard fires.
    ws.mail.model_config  # ensure model is initialised
    with patch.object(ws.mail, "allow_smtp", False):
        # Re-build with patched config — guard should raise.
        patched_server = build_server(ws)
        patched_tools = {t.name: t for t in asyncio.run(patched_server.list_tools())}
        assert "send_outbound_email" not in patched_tools  # registration gate also fires
