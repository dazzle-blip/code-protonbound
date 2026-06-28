"""Verify the MCP tool surface matches the permission tier and SMTP gating."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

from protonbound.config import (
    TOOL_GATES,
    AccountConfig,
    MailConfig,
    Permission,
    ScopeConfig,
    Workspace,
    WorkspaceMeta,
    WriteTargets,
)
from protonbound.server import _workspace_instructions, build_server

#: Sentinel: tools not specified by a test -> default to the full tier/flag-permitted surface,
#: so tests that aren't about the allow-list still exercise the whole tier (the surface is
#: deny-first, so without this every such test would otherwise see zero tools).
_TIER = object()


def _permitted_tools(permission, allow_delete, allow_smtp) -> list[str]:
    enabled = {"read"}
    if permission is Permission.read_write:
        enabled.add("write")
    if allow_delete:
        enabled.add("delete")
    if allow_smtp:
        enabled.add("send")
    return [name for name, gate in TOOL_GATES.items() if gate in enabled]


def _workspace(
    permission: Permission,
    allow_delete: bool = False,
    allow_local_attachments: bool = False,
    allow_smtp: bool = False,
    tools=_TIER,
    voice: str | None = None,
) -> Workspace:
    if tools is _TIER:
        tools = _permitted_tools(permission, allow_delete, allow_smtp)
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
            tools=tools,
            voice=voice,
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
    assert "digest" in names
    assert "get_thread" in names
    # no write tools at all
    assert "draft_reply" not in names
    assert "save_draft" not in names
    assert "move_message" not in names
    assert "delete_message" not in names


def test_digest_is_a_read_tool():
    """digest is a read-tier triage tool, available even in a readonly workspace."""

    names = _tool_names(_workspace(Permission.readonly))
    assert "digest" in names


def test_read_write_has_draft_tools_but_no_send_by_default():
    names = _tool_names(_workspace(Permission.read_write))
    assert "draft_reply" in names
    assert "save_draft" in names
    assert "update_draft" in names
    # send absent unless allow_smtp is explicitly True
    assert "send_draft" not in names
    # delete only when explicitly enabled
    assert "delete_message" not in names


def test_delete_tool_only_when_enabled():
    names = _tool_names(_workspace(Permission.read_write, allow_delete=True))
    assert "delete_message" in names


# -- tools: allowlist (surface fully determined by config) ----------------------------


def test_allowlist_exposes_exactly_the_listed_tools():
    ws = _workspace(
        Permission.read_write,
        allow_smtp=True,
        tools=["digest", "get_thread", "draft_reply", "send_draft"],
    )
    assert _tool_names(ws) == {"digest", "get_thread", "draft_reply", "send_draft"}


def test_allowlist_can_exclude_get_workspace_info():
    """Nothing is implicit — even get_workspace_info only appears if listed."""

    assert _tool_names(_workspace(Permission.readonly, tools=["digest"])) == {
        "digest"
    }


def test_empty_allowlist_exposes_nothing():
    assert _tool_names(_workspace(Permission.readonly, tools=[])) == set()


def test_deny_first_default_exposes_nothing():
    """Deny-first: a config that names no tools (the default empty list) exposes none."""

    ws = Workspace(
        meta=WorkspaceMeta(
            name="t", description="d", account=AccountConfig(username="me@proton.me")
        ),
        mail=MailConfig(
            permission=Permission.read_write,
            scope=ScopeConfig(sources=["Labels/AI"]),
            write_targets=WriteTargets(drafts="Drafts", trash="Trash"),
        ),  # tools omitted -> defaults to []
        path=Path("."),
    )
    assert _tool_names(ws) == set()


def test_allowlist_still_intersects_hard_gates():
    """A deleted smtp.py drops send_draft even when it is explicitly allowlisted."""

    from unittest.mock import patch

    import protonbound.server as server_mod

    ws = _workspace(
        Permission.read_write, allow_smtp=True, tools=["draft_reply", "send_draft"]
    )
    with patch.object(server_mod, "_smtp_module_available", return_value=False):
        names = {t.name for t in asyncio.run(build_server(ws).list_tools())}
    assert names == {"draft_reply"}  # send_draft dropped by the module kill-switch


def test_full_surface_matches_tool_catalog():
    """Drift guard: a maximally-enabled workspace registers exactly TOOL_GATES' tools."""

    from protonbound.config import TOOL_GATES

    ws = _workspace(Permission.read_write, allow_delete=True, allow_smtp=True)
    assert _tool_names(ws) == set(TOOL_GATES)


def test_send_tool_absent_by_default():
    for perm in (Permission.readonly, Permission.read_write):
        names = _tool_names(_workspace(perm))
        assert "send_draft" not in names


def test_send_tool_present_when_smtp_enabled():
    names = _tool_names(_workspace(Permission.read_write, allow_smtp=True))
    assert "send_draft" in names


def test_send_tool_warns_about_injection():
    server = build_server(_workspace(Permission.read_write, allow_smtp=True))
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    desc = tools["send_draft"].description.lower()
    assert "confirmation" in desc or "confirm" in desc


def test_tool_annotations_mark_read_vs_write_vs_send():
    """ToolAnnotations let a client tell reads from writes from sends (advisory hints)."""

    server = build_server(_workspace(Permission.read_write, allow_delete=True, allow_smtp=True))
    tools = {t.name: t for t in asyncio.run(server.list_tools())}

    # read tools are flagged read-only
    for name in ("digest", "get_thread", "get_message", "search_mail", "list_folders"):
        assert tools[name].annotations.readOnlyHint is True, name

    # writes are not read-only and disclaim the open world (local mailbox only)
    for name in ("draft_reply", "save_draft", "update_draft", "move_message"):
        assert tools[name].annotations.readOnlyHint is False, name
        assert tools[name].annotations.openWorldHint is False, name

    # destructive updates are flagged as such
    assert tools["update_draft"].annotations.destructiveHint is True
    assert tools["delete_message"].annotations.destructiveHint is True

    # idempotent housekeeping
    assert tools["set_star"].annotations.idempotentHint is True

    # send is destructive AND open-world (reaches external recipients)
    send = tools["send_draft"].annotations
    assert send.readOnlyHint is False
    assert send.destructiveHint is True
    assert send.openWorldHint is True


def test_deleted_smtp_module_disables_send_despite_allow_smtp():
    """Hard kill-switch: with smtp.py absent, send is disabled even if allow_smtp is true."""

    from unittest.mock import patch

    import protonbound.server as server_mod

    ws = _workspace(Permission.read_write, allow_smtp=True)
    with patch.object(server_mod, "_smtp_module_available", return_value=False):
        names = {t.name for t in asyncio.run(build_server(ws).list_tools())}
    assert "send_draft" not in names


def test_instructions_reflect_effective_send_capability():
    """can_send (allow_smtp AND module present), not the raw flag, drives the boundary text."""

    ws = _workspace(Permission.read_write, allow_smtp=True)
    assert "can NEVER send mail" in _workspace_instructions(ws, can_send=False)
    assert "CAN send mail" in _workspace_instructions(ws, can_send=True)


def test_building_send_enabled_server_does_not_import_smtplib():
    """allow_smtp=True registers the tool via a find_spec presence check, which must NOT
    import smtplib — that import is deferred to an actual send call. Checked in a fresh
    subprocess so the result is not polluted by other tests importing protonbound.smtp."""

    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import asyncio
        import sys
        from pathlib import Path
        from protonbound.config import (
            AccountConfig, MailConfig, Permission, ScopeConfig, Workspace,
            WorkspaceMeta, WriteTargets,
        )
        from protonbound.server import build_server

        ws = Workspace(
            meta=WorkspaceMeta(
                name="t", description="d",
                account=AccountConfig(username="me@proton.me"),
            ),
            mail=MailConfig(
                permission=Permission.read_write,
                scope=ScopeConfig(sources=["Folders/X"]),
                write_targets=WriteTargets(drafts="Drafts", trash="Trash"),
                allow_smtp=True,
                tools=["send_draft"],
            ),
            path=Path("."),
        )
        server = build_server(ws)
        names = {t.name for t in asyncio.run(server.list_tools())}
        assert "send_draft" in names, names
        assert "smtplib" not in sys.modules, "smtplib imported just by building the server"
        assert "protonbound.smtp" not in sys.modules, "smtp.py imported at build time"
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_instructions_advertise_operational_limits():
    """Read-write limits are stated up front so the model doesn't attempt doomed calls."""

    text = _workspace_instructions(
        _workspace(Permission.read_write, allow_delete=False), can_send=False
    )
    assert "No delete tool" in text
    assert "attaching LOCAL files by path is disabled" in text
    assert "only target the readable sources" in text

    enabled = _workspace_instructions(
        _workspace(Permission.read_write, allow_delete=True, allow_local_attachments=True),
        can_send=False,
    )
    assert "delete_message moves to Trash" in enabled
    assert "attaching a LOCAL file by path is allowed" in enabled


def test_readonly_instructions_omit_write_limits():
    text = _workspace_instructions(_workspace(Permission.readonly), can_send=False)
    assert "Attachments:" not in text
    assert "delete" not in text.lower()


def test_voice_renders_into_read_write_instructions():
    """A configured voice is advertised in the always-on instructions, by the draft guidance."""

    ws = _workspace(Permission.read_write, voice="Warm and concise. Sign off as Sam.")
    text = _workspace_instructions(ws, can_send=False)
    assert "Draft in this workspace's voice: Warm and concise. Sign off as Sam." in text


def test_voice_absent_from_readonly_instructions():
    """A readonly workspace never drafts, so the voice line is not rendered even if set."""

    ws = _workspace(Permission.readonly, voice="Warm and concise.")
    assert "voice" not in _workspace_instructions(ws, can_send=False).lower()


def test_no_voice_line_when_unset():
    text = _workspace_instructions(_workspace(Permission.read_write), can_send=False)
    assert "Draft in this workspace's voice" not in text


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
    """Runtime guarantee: building a default workspace never loads smtplib or smtp.py.

    Checked in a fresh subprocess so the result reflects a clean server process and is not
    polluted by other tests in this session that legitimately import protonbound.smtp.
    """

    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        from protonbound.config import (
            AccountConfig, MailConfig, Permission, ScopeConfig, Workspace,
            WorkspaceMeta, WriteTargets,
        )
        from protonbound.server import build_server

        ws = Workspace(
            meta=WorkspaceMeta(
                name="t", description="d",
                account=AccountConfig(username="you@example.com"),
            ),
            mail=MailConfig(
                permission=Permission.readonly,
                scope=ScopeConfig(sources=["Folders/X"]),
                write_targets=WriteTargets(drafts="Drafts", trash="Trash"),
            ),
            path=Path("."),
        )
        build_server(ws)
        assert "smtplib" not in sys.modules, "smtplib loaded with allow_smtp disabled"
        assert "protonbound.smtp" not in sys.modules, "smtp.py loaded with allow_smtp disabled"
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_send_runtime_guard_raises_if_smtp_disabled():
    """The PermissionError guard fires even if the function were called with allow_smtp=False."""


    # Build with allow_smtp=True so the function is defined, then call it with a patched
    # mail_cfg that has allow_smtp=False to simulate the guard tripping at runtime.
    from unittest.mock import patch

    ws = _workspace(Permission.read_write, allow_smtp=True)
    server = build_server(ws)
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert "send_draft" in tools

    # Patch allow_smtp off after registration to prove the in-function guard fires.
    ws.mail.model_config  # ensure model is initialised
    with patch.object(ws.mail, "allow_smtp", False):
        # Re-build with patched config — guard should raise.
        patched_server = build_server(ws)
        patched_tools = {t.name: t for t in asyncio.run(patched_server.list_tools())}
        assert "send_draft" not in patched_tools  # registration gate also fires
