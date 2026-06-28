"""Workspace configuration models and loader.

A workspace is a single committed YAML file (``workspaces/<name>.yaml``) with two parts:

* top level — ``name``, agent-facing ``description``, and the Bridge IMAP ``account``;
* a ``mail:`` section — permission tier, read scope (deny-by-default allow-lists) and the
  named write-target mailboxes.

No secrets live in this file; the Bridge password is read from the environment at connect
time (see :mod:`protonbound.mail`). All models use ``extra="forbid"`` so an unknown key is
a hard error rather than a silently ignored typo.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

#: A workspace name flows into the MCP server id ``protonbound-<name>`` and the tool-name
#: prefix ``mcp__protonbound-<name>__<tool>``. Those break on spaces and punctuation, so the
#: name must be a conservative slug: start alphanumeric, then alphanumerics / ``-`` / ``_``.
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


class Permission(str, Enum):
    """Mail permission tiers. Sending is a separate opt-in (allow_smtp on MailConfig)."""

    readonly = "readonly"
    read_write = "read-write"


class AccountConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    imap_host: str = "127.0.0.1"
    imap_port: int = 1143
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 1025
    # The Bridge IMAP/SMTP login (the primary account address). Same across all workspaces.
    username: str
    # Default sender identity for newly composed drafts. Use this to draft *as* an alias
    # rather than the primary account. If unset, falls back to `username`. Replies prefer
    # whichever workspace alias the original was addressed to (see ProtonMailClient).
    from_address: str | None = None
    # Optional: pin Proton Bridge's TLS certificate by SHA-256 fingerprint (hex, colons
    # optional). When set, the server refuses to connect — before sending credentials — if
    # Bridge presents a different cert, defeating local TLS interception. Capture it with
    # `protonbound --show-cert --workspace <file>`.
    bridge_cert_sha256: str | None = None

    @field_validator("bridge_cert_sha256")
    @classmethod
    def _normalize_cert_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        norm = value.replace(":", "").replace(" ", "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", norm):
            raise ValueError(
                "bridge_cert_sha256 must be a SHA-256 fingerprint (64 hex chars, colons "
                "optional)"
            )
        return norm


class ScopeConfig(BaseModel):
    """What the agent may *read*. Deny-by-default, combination (AND) semantics."""

    model_config = ConfigDict(extra="forbid")

    # Allowed source mailboxes (folders + labels). Required and non-empty: an empty
    # allow-list means the agent sees nothing, so we make that explicit, not accidental.
    sources: list[str]
    # Curation gate, ANDed with sources: when true only starred messages are in scope.
    require_starred: bool = False
    # Optional address allow-list, ANDed with sources. Empty => sources alone gate.
    addresses: list[str] = Field(default_factory=list)

    @field_validator("sources")
    @classmethod
    def _sources_non_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError(
                "scope.sources must be a non-empty allow-list (scope is deny-by-default)"
            )
        return value


class WriteTargets(BaseModel):
    """Named system mailboxes used as write destinations only (not read scope)."""

    model_config = ConfigDict(extra="forbid")

    drafts: str | None = None
    trash: str | None = None


#: Canonical catalog of every tool the server can expose, mapped to the capability gate that
#: is its hard prerequisite:
#:   "read"   — always permitted (a workspace always has read scope);
#:   "write"  — requires ``permission: read-write``;
#:   "delete" — requires ``allow_delete`` (and a trash target);
#:   "send"   — requires ``allow_smtp`` (and the smtp module present, checked at build time).
#: The deny-first ``tools:`` allow-list may name only tools whose prerequisite the config
#: already satisfies; it *selects* among permitted tools, it never grants a capability.
#: ``server.build_server`` registers exactly the named tools, and ``test_tool_surface`` asserts
#: this catalog never drifts from the tools the server actually defines.
TOOL_GATES: dict[str, str] = {
    "get_workspace_info": "read",
    "list_folders": "read",
    "digest": "read",
    "get_thread": "read",
    "get_message": "read",
    "search_mail": "read",
    "draft_reply": "write",
    "save_draft": "write",
    "update_draft": "write",
    "set_read": "write",
    "set_star": "write",
    "move_message": "write",
    "set_label": "write",
    "delete_message": "delete",
    "send_draft": "send",
}


class MailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permission: Permission
    scope: ScopeConfig
    write_targets: WriteTargets = Field(default_factory=WriteTargets)
    # Whether delete_message is offered (moves to write_targets.trash).
    allow_delete: bool = False
    # Whether drafts may attach arbitrary *local files* by path. Off by default: re-attaching
    # a file already on in-scope mail is always allowed, but reading the local filesystem is
    # an extra surface the workspace owner must deliberately opt into.
    allow_local_attachments: bool = False
    # Per-attachment size ceiling in megabytes (Proton's own message limit is ~25 MB total).
    max_attachment_mb: int = Field(default=25, gt=0)
    # Enable outbound SMTP send via Bridge. Off by default: when False, smtplib is never
    # imported and the send tool is never registered, so the agent is structurally blind to
    # any send capability. Set True only in workspaces where human-supervised sending is
    # intentional and accepted.
    allow_smtp: bool = False
    # Optional, workspace-defined plain-text signature. When set, the draft/send tools can
    # append it beneath the message (separated by the RFC 3676 "-- " delimiter). The text is
    # appended verbatim by code — the model never authors or edits it, it only passes a bool
    # choosing whether to include it. Unset => no signature is ever added.
    signature: str | None = None
    # Optional, workspace-defined drafting voice/style guidance. When set on a read-write
    # workspace it is rendered into the always-on server ``instructions`` (next to the draft
    # guidance), so every reply composed here is authored in this voice. Keep it to *how* to
    # write (tone, sign-off, CC policy) — *when* to use the workspace belongs in ``description``.
    # Unset => no voice line is added.
    voice: str | None = None
    # Explicit allow-list of the exact tools to expose to the model. DENY-FIRST: the surface is
    # exactly the tools named here and nothing else — not even get_workspace_info unless listed.
    # The default is an empty list, so a workspace that names no tools exposes none (the safe
    # default). A name may appear only if its prerequisite capability is enabled (see
    # TOOL_GATES): the list *narrows* what the permission tier + allow_* flags permit, it never
    # grants a capability. So the live surface is always (tier/flag-permitted) ∩ (this list).
    tools: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_targets(self) -> MailConfig:
        if self.permission is Permission.read_write and not self.write_targets.drafts:
            raise ValueError(
                "write_targets.drafts is required when permission is 'read-write'"
            )
        if self.allow_delete and not self.write_targets.trash:
            raise ValueError(
                "write_targets.trash is required when allow_delete is true"
            )
        return self

    @model_validator(mode="after")
    def _validate_tool_allowlist(self) -> MailConfig:
        """The ``tools:`` allow-list must name real tools whose prerequisite is already enabled.

        This keeps the list a pure *selection* of permitted tools: it cannot name a tool the
        tiers/flags don't permit (which would be a silent no-op or, worse, read as granting a
        capability). Unknown names are rejected too, so a typo fails loudly rather than silently
        dropping a tool the owner meant to expose. An empty list is valid — it exposes nothing.
        """

        unknown = [t for t in self.tools if t not in TOOL_GATES]
        if unknown:
            raise ValueError(
                f"tools allowlist names unknown tool(s) {unknown}; valid names are "
                f"{sorted(TOOL_GATES)}"
            )
        for tool in self.tools:
            gate = TOOL_GATES[tool]
            if gate == "write" and not self.can_write:
                raise ValueError(
                    f"tools allowlist includes {tool!r}, which needs 'permission: read-write'"
                )
            if gate == "delete" and not self.allow_delete:
                raise ValueError(
                    f"tools allowlist includes {tool!r}, which needs 'allow_delete: true'"
                )
            if gate == "send" and not self.allow_smtp:
                raise ValueError(
                    f"tools allowlist includes {tool!r}, which needs 'allow_smtp: true'"
                )
        return self

    @property
    def can_write(self) -> bool:
        return self.permission is Permission.read_write

    def exposes(self, tool: str) -> bool:
        """Whether ``tool`` is selected by the deny-first allow-list. Only names present in
        ``tools`` pass; an empty list exposes nothing. Prerequisite gating (read-write /
        allow_delete / allow_smtp) is applied separately in build_server, so the live surface
        is the intersection of the two."""

        return tool in self.tools


class WorkspaceMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    account: AccountConfig

    @field_validator("name")
    @classmethod
    def _name_is_safe_slug(cls, value: str) -> str:
        if not _SAFE_NAME_RE.fullmatch(value):
            raise ValueError(
                f"workspace name {value!r} must be a slug (letters, digits, '-' or '_', "
                "starting alphanumeric). It becomes the MCP server id 'protonbound-<name>' "
                "and the tool-name prefix, which break on spaces or other characters. Put any "
                "display/stage name in 'description' instead."
            )
        return value


class Workspace(BaseModel):
    """A fully loaded workspace: metadata + mail config + its on-disk location."""

    model_config = ConfigDict(extra="forbid")

    meta: WorkspaceMeta
    mail: MailConfig
    path: Path

    @model_validator(mode="after")
    def _send_identity_in_scope(self) -> Workspace:
        """A send-enabled workspace may only send *as* one of its in-scope addresses.

        When ``allow_smtp`` is on and ``scope.addresses`` declares the workspace's own
        aliases, the configured sender (``from_address`` else ``username``) must be one of
        them — so e.g. a 'career' workspace can never send from the 'comedy' alias. With no
        ``scope.addresses`` there is nothing to restrict against, so the check is skipped.
        """

        if not self.mail.allow_smtp or not self.mail.scope.addresses:
            return self
        # Local import: scope imports from config, so importing it at call time (not module
        # load) avoids a circular import while reusing the one canonical address normaliser.
        from .scope import normalize_address

        sender = self.meta.account.from_address or self.meta.account.username
        allowed = {normalize_address(a) for a in self.mail.scope.addresses}
        if normalize_address(sender) not in allowed:
            raise ValueError(
                f"account sender {sender!r} is not within scope.addresses "
                f"{self.mail.scope.addresses!r}: a send-enabled (allow_smtp) workspace may "
                "only send as one of its in-scope addresses. Set account.from_address to one "
                "of them."
            )
        return self


def _read_yaml(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Missing required config file: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file {path} must contain a YAML mapping at its root")
    return data


def load_workspace(path: str | Path) -> Workspace:
    """Load and validate a workspace YAML file into a :class:`Workspace`.

    ``path`` is the workspace file (``workspaces/<name>.yaml``): ``name``/``description``/
    ``account`` at the top level and the permission/scope settings under a ``mail:`` key.
    """

    file = Path(path).expanduser().resolve()
    if not file.is_file():
        raise FileNotFoundError(f"Workspace file not found: {file}")

    data = _read_yaml(file)
    if "mail" not in data:
        raise ValueError(f"{file.name} must contain a 'mail:' section")
    mail_data = data.pop("mail")
    if not isinstance(mail_data, dict):
        raise ValueError(f"{file.name} 'mail:' section must be a mapping")

    meta = WorkspaceMeta(**data)  # extra="forbid" rejects stray top-level keys
    mail = MailConfig(**mail_data)
    return Workspace(meta=meta, mail=mail, path=file)
