"""Config loading and validation tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from protonbound.config import AccountConfig, Permission, load_workspace


def write_workspace(tmp_path: Path, workspace_yaml: str, mail_yaml: str) -> Path:
    """Compose the meta + mail fragments into a single workspace YAML file (mail nested)."""

    meta = textwrap.dedent(workspace_yaml).strip("\n")
    mail = textwrap.indent(textwrap.dedent(mail_yaml).strip("\n"), "  ")
    file = tmp_path / "ws.yaml"
    file.write_text(f"{meta}\nmail:\n{mail}\n", encoding="utf-8")
    return file


VALID_WORKSPACE = """
    name: clients
    description: Client mail.
    account:
      username: me@proton.me
"""


def test_valid_workspace_loads(tmp_path):
    path = write_workspace(
        tmp_path,
        VALID_WORKSPACE,
        """
        permission: read-write
        scope:
          sources: ["Labels/AI"]
        write_targets:
          drafts: Drafts
        """,
    )
    ws = load_workspace(path)
    assert ws.meta.name == "clients"
    assert ws.mail.permission is Permission.read_write
    assert ws.mail.can_write is True


def test_empty_sources_rejected(tmp_path):
    path = write_workspace(
        tmp_path,
        VALID_WORKSPACE,
        """
        permission: readonly
        scope:
          sources: []
        """,
    )
    with pytest.raises(ValidationError):
        load_workspace(path)


def test_read_write_requires_drafts_target(tmp_path):
    path = write_workspace(
        tmp_path,
        VALID_WORKSPACE,
        """
        permission: read-write
        scope:
          sources: ["Labels/AI"]
        """,
    )
    with pytest.raises(ValidationError):
        load_workspace(path)


def test_allow_delete_requires_trash_target(tmp_path):
    path = write_workspace(
        tmp_path,
        VALID_WORKSPACE,
        """
        permission: read-write
        scope:
          sources: ["Labels/AI"]
        write_targets:
          drafts: Drafts
        allow_delete: true
        """,
    )
    with pytest.raises(ValidationError):
        load_workspace(path)


def test_bad_permission_rejected(tmp_path):
    path = write_workspace(
        tmp_path,
        VALID_WORKSPACE,
        """
        permission: read-write-execute
        scope:
          sources: ["Labels/AI"]
        write_targets:
          drafts: Drafts
        """,
    )
    with pytest.raises(ValidationError):
        load_workspace(path)


def test_name_with_space_rejected(tmp_path):
    """A name with a space would corrupt the MCP server id / tool-name prefix."""

    path = write_workspace(
        tmp_path,
        """
        name: Some Name
        description: Team mail.
        account:
          username: me@proton.me
        """,
        """
        permission: readonly
        scope:
          sources: ["Labels/AI"]
        """,
    )
    with pytest.raises(ValidationError):
        load_workspace(path)


def test_slug_name_accepted(tmp_path):
    path = write_workspace(
        tmp_path,
        """
        name: some-name_2
        description: Team mail.
        account:
          username: me@proton.me
        """,
        """
        permission: readonly
        scope:
          sources: ["Labels/AI"]
        """,
    )
    assert load_workspace(path).meta.name == "some-name_2"


def test_unknown_key_rejected(tmp_path):
    path = write_workspace(
        tmp_path,
        VALID_WORKSPACE,
        """
        permission: readonly
        scope:
          sources: ["Labels/AI"]
        surprise: true
        """,
    )
    with pytest.raises(ValidationError):
        load_workspace(path)


def test_bridge_cert_fingerprint_is_normalized():
    fp = "AB:CD:" + "ef" * 30  # colons + mixed case, 64 hex digits total (4 + 60)
    account = AccountConfig(username="me@proton.me", bridge_cert_sha256=fp)
    assert account.bridge_cert_sha256 == ("abcd" + "ef" * 30)  # lowercased, no colons


def test_bad_bridge_cert_fingerprint_rejected():
    with pytest.raises(ValidationError):
        AccountConfig(username="me@proton.me", bridge_cert_sha256="not-a-fingerprint")
