# ProtonBound

A lightweight **MCP server** that gives an AI agent a **scoped, draft-first** view into
your Proton Mail through **Proton Bridge**.

The scope is enforced in code, not by prompting: the agent physically cannot read or touch
mail outside the workspace you configure. By default **it can never send** — replies are
saved as drafts for you to review and dispatch yourself. Outbound SMTP is an explicit
opt-in (`allow_smtp: true` in the workspace file) that keeps the tool structurally absent
until you decide the use-case warrants it.

## What it does (and doesn't)

- ✅ Read mail within a configured scope (specific folders/labels, optionally only starred,
  optionally only certain correspondents — including mail where you were **BCC'd**).
- ✅ Work **thread-centric**: list and read whole conversations.
- ✅ **Search** in-scope mail by subject/body/sender/recency/read-status.
- ✅ **Draft** replies, new messages, and **update** existing drafts (all saved to your Drafts).
- ✅ Optional housekeeping: mark read/unread, star, move/label within scope, optional delete.
- ✅ Optional **outbound SMTP send** via Bridge — off by default; enable per-workspace with
  `allow_smtp: true`. When disabled, `smtplib` is never imported and the send tool never
  appears in the MCP tool list, so the agent is structurally blind to any send capability.
- ✅ **Developer inspection CLI** (`--inspect`) — shows the exact JSON payloads the LLM
  receives, including fencing tags and opaque tokens, without routing mail through an AI.
- ❌ No calendar, no contacts. Mail only.

> Proton Bridge exposes mail over local IMAP/SMTP. This server uses **IMAP for reading** and
> Bridge SMTP for sending only when `allow_smtp: true`.

## How it compares

Other Proton MCP servers exist. This comparison is **Proton-only and security-first**: it
ignores features that don't actually talk to Proton — e.g. `proton-mcp`'s "Calendar" is a
generic CalDAV client pointed at a self-hosted **Radicale** server on `127.0.0.1:5232`, not
Proton Calendar. Reviewed: **ProtonBound 0.1.0**, `protonmail-pro-mcp` **1.0.0**, `proton-mcp`
**1.0.0**, `proton-bridge-mcp` (no version tag).

**Platform**

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp | proton-bridge-mcp |
|---|---|---|---|---|
| Stack | Python | Node / TS | Node / JS | Python |
| Proton transport | Bridge IMAP only | Bridge IMAP + remote SMTP | Bridge IMAP + SMTP | Bridge IMAP + SMTP |

**Security model**

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp | proton-bridge-mcp |
|---|---|---|---|---|
| **Can send mail** | **No by default** — `allow_smtp: false`; `smtp.py` never imported, send tool never registered. Opt-in with `allow_smtp: true`. | ⚠️ Yes | ⚠️ Yes | ⚠️ Yes |
| **Human review before send** | **Yes — drafts only** | ⚠️ No — sends directly | ⚠️ No — sends directly | ⚠️ No — sends directly |
| **Scoped access** (deny-by-default folders / addresses / starred) | **Yes** | No — full mailbox | No — full mailbox | No — full mailbox |
| **Per-workspace isolation** | **Yes — one scope per process** | No | No | No |
| **Opaque message ids** (session-scoped whitelist, CRC-verified) | **Yes** | No | No | No |
| **Body fencing** (untrusted content labelled, boundary defanged) | **Yes** | No | No | No |

**Credentials & connection**

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp | proton-bridge-mcp |
|---|---|---|---|---|
| **TLS cert pinning** for Bridge connection | **Yes** — explicit SHA-256 pin in config (`bridge_cert_sha256`); opt-in but a hard match when set; use `--show-cert` to capture | ⚠️ No | ⚠️ No | Yes — automatic TOFU: cert captured on first connection and stored; on by default but vulnerable if first run is already intercepted |
| **Credential storage** | **OS keyring** (`keyring` package — macOS/Windows/Linux) or env var | ⚠️ Account creds → remote SMTP | Bridge password + pass-cli | macOS Keychain only (`/usr/bin/security`) or env var |
| **Reads password vault / TOTP** | No | No | ⚠️ Yes (`pass__get_item` / `get_totp`) | No |

**Destructive operations**

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp | proton-bridge-mcp |
|---|---|---|---|---|
| **Delete** | Opt-in; moves to Trash | ⚠️ Permanent delete | Delete mail | Requires `acknowledged=true` |
| **Other mutations** | Draft save/update only | — | — | Move / flag; each requires `acknowledged=true` |

**Attachments**

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp | proton-bridge-mcp |
|---|---|---|---|---|
| Read attachment list (metadata to LLM) | Yes | Yes | Yes | Yes |
| Attachment content to LLM | **Opt-in**, size-capped | Yes (bundled with send) | Yes — base64-encoded inline | Explicit download tool only (requires `acknowledged=true`) |
| Re-attach to draft without LLM pass-through | **Yes — in-scope mail only** | No | No | No |
| Attach local files to draft | **Opt-in**, size-capped | Yes | No | No — download to disk only |

**Email processing**

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp | proton-bridge-mcp |
|---|---|---|---|---|
| Thread-centric API (list → get_thread → get_message) | **Yes** | No | No — threading metadata only; no server-side grouping | No — In-Reply-To/References passed as raw fields |
| Thread folding + quote de-duplication | **Yes** — repeated quoted text collapses; edited quotes preserved | No | No | No |
| HTML → Markdown conversion | **Yes** | Source not public | No — returns `mail.text` or raw HTML as-is | No — HTML returned as-is |
| Header-only fetch for listing | **Yes** | Source not public | Yes — uses `'HEADER'` param for listings | Yes — `BODY.PEEK[HEADER.FIELDS ...]` for listings |
| Persistent connection with idle probe | **Yes** — reused; NOOP probe only after 30 s idle | Source not public | No — new connection per operation | Yes — long-lived; NOOP before each reuse |
| Loopback socket tuning (TCP_NODELAY, SO_RCVBUF) | **Yes** | No | No | No |
| Concurrent tool call safety | **Yes** — `threading.RLock` serialises IMAP ops | Source not public | Sequential — no parallelism within a request | Yes — `asyncio.Lock` per connection |

**Why the security columns matter.** Every email body is attacker-controlled text, so an
agent reading your mail can be steered by a malicious message (*prompt injection*) into using
whatever tools it holds. ProtonBound is built to make a hijacked agent harmless:

- **Send is off by default** — with `allow_smtp: false` (the default), `smtplib` is never
  imported and the send tool is never registered; the agent is structurally blind to it. When
  `allow_smtp: true` is set, a runtime `PermissionError` guard fires as the first line of the
  send function, independent of the registration gate, so the boundary holds even through
  future refactors. The worst case in the default config is a draft *you* review.
- **Deny-by-default scope** — it only ever sees the folders/addresses you list (optionally
  starred-only), and each workspace runs as its own isolated process, so one agent can't reach
  another's mail.
- **Nothing to exfiltrate** — there is no Pass/Drive integration; the only secret is the local
  Bridge password, which never leaves your machine and can't unlock your Proton account.

The others are more capable — autonomous send, and in `proton-mcp`'s case read access to your
password vault — but that capability *is* the blast radius an injected instruction can abuse.
`proton-bridge-mcp` shares the Python/IMAP approach and adds TLS cert pinning (TOFU-style),
but retains full SMTP send and no folder-level scope controls. ProtonBound deliberately trades
breadth for a tight, auditable security boundary.

## How scope works

Each *workspace* is a single committed YAML file, `workspaces/<name>.yaml` (name/description/
account plus a `mail:` section for permission, scope, and write targets). Scope is
**deny-by-default** and combines (AND) up to three filters — a message is in scope only if
**all** apply:

1. it is in an allowed **source** mailbox (`scope.sources`);
2. if `require_starred: true`, it is **starred**;
3. if `scope.addresses` is set, one of those addresses appears in From/To/Cc **or** the
   delivery headers (`Delivered-To` / `X-Original-To` / `Envelope-To` — this is how BCC'd
   mail to your aliases is matched).

See [`workspaces/example-clients.yaml`](workspaces/example-clients.yaml) for a fully
commented example. One server instance serves exactly one workspace.

## Prerequisites

1. **Proton Bridge** installed, running, and signed in. Add your account and note the
   per-account **IMAP username** and **Bridge password** (Bridge → account → *Mailbox
   configuration*). This is the Bridge password, **not** your Proton login password.
2. **Python 3.11+** and [**uv**](https://docs.astral.sh/uv/).

## Install

```bash
git clone <this-repo> code-protonbound
cd code-protonbound
uv sync
```

Run the tests (no Proton Bridge needed — scope logic is pure):

```bash
uv run pytest
```

<details>
<summary>No <code>uv</code>? Use a plain venv + pip instead</summary>

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

pip install -e . pytest
pytest
protonbound --workspace workspaces/my-clients.yaml   # after configuring (see below)
```

Requires a real Python 3.11+ on `PATH` (the Microsoft Store stub won't work).
</details>

## Configure a workspace

Copy the example and edit it:

```bash
# Linux/macOS
cp workspaces/example-clients.yaml workspaces/my-clients.yaml
```

```powershell
# Windows (PowerShell)
Copy-Item workspaces/example-clients.yaml workspaces/my-clients.yaml
```

Edit `workspaces/my-clients.yaml`: your `username`, and under `mail:` your scope,
permission tier, and the real names of your Drafts/Trash mailboxes as Bridge reports them.

**Account options** (all under `account:`):

| Field | Default | Description |
|---|---|---|
| `username` | *(required)* | Bridge IMAP/SMTP login — your primary Proton address |
| `imap_host` | `127.0.0.1` | Bridge host |
| `imap_port` | `1143` | Bridge IMAP port |
| `smtp_host` | `127.0.0.1` | Bridge SMTP host (used only when `allow_smtp: true`) |
| `smtp_port` | `1025` | Bridge SMTP port (used only when `allow_smtp: true`) |
| `from_address` | same as `username` | Sender identity for drafts and outbound mail (use to send *as* an alias) |
| `bridge_cert_sha256` | *(unset)* | SHA-256 fingerprint to pin Bridge's TLS cert (see below) |

## Store the Bridge password

Preferred — keep the secret in your **OS keyring** (Windows Credential Manager / macOS
Keychain / Linux Secret Service), keyed by the workspace's IMAP username:

```bash
uv run protonbound --set-password --workspace workspaces/my-clients.yaml
# prompts for the Bridge password and stores it; never written to a file or env var
```

At runtime the server reads the keyring first and falls back to the
`PROTONBOUND_BRIDGE_PASSWORD` environment variable if the keyring has no entry — so the env
var still works for headless/CI use where no keyring backend exists.

## Pin the Bridge TLS certificate (optional but recommended)

Proton Bridge listens on localhost with a self-signed TLS certificate. Pinning it by
SHA-256 fingerprint means the server will refuse to connect — and therefore refuse to send
your credentials — if Bridge ever presents a different certificate (e.g. due to a local TLS
interception proxy).

First, capture the current fingerprint:

```bash
uv run protonbound --show-cert --workspace workspaces/my-clients.yaml
# prints: Bridge TLS cert SHA-256: ab:cd:ef:...
```

Then add the fingerprint to your workspace file under `account:`:

```yaml
account:
  username: you@pm.me
  bridge_cert_sha256: "ab:cd:ef:..."   # colons optional; 64 hex chars
```

On the next launch the server validates the cert before authenticating. If it mismatches,
the connection is aborted with a clear error.

## Try it locally with the MCP Inspector

```bash
PROTONBOUND_BRIDGE_PASSWORD="<bridge-password>" \
  uv run protonbound --workspace workspaces/my-clients.yaml
```

Or with the interactive inspector:

```bash
PROTONBOUND_WORKSPACE=workspaces/my-clients.yaml \
PROTONBOUND_BRIDGE_PASSWORD="<bridge-password>" \
  uv run mcp dev src/protonbound/__main__.py
```

On **Windows PowerShell**, set the env vars first:

```powershell
$env:PROTONBOUND_BRIDGE_PASSWORD = "<bridge-password>"
uv run protonbound --workspace workspaces/my-clients.yaml
```

## Register with an MCP client

Add **one entry per workspace** to your client config (e.g. Claude Desktop's
`claude_desktop_config.json`, or a project `.mcp.json`):

```json
{
  "mcpServers": {
    "protonbound-clients": {
      "command": "uv",
      "args": ["run", "protonbound", "--workspace", "workspaces/my-clients.yaml"],
      "env": { "PROTONBOUND_BRIDGE_PASSWORD": "<bridge-password>" }
    }
  }
}
```

> On Windows, use the absolute path to the workspace and ensure `uv` is on `PATH` (or give
> the full path to `uv.exe`). Bridge's default ports (IMAP 1143) are identical on both OSes.

### Picking a permission tier

| `permission` | Reads | Drafts & housekeeping | Sends |
|--------------|:-----:|:---------------------:|:-----:|
| `readonly`   | ✅    | ❌                    | ❌ by default |
| `read-write` | ✅    | ✅                    | ❌ by default |

Sending is a separate opt-in flag, independent of the permission tier:

| `mail:` flag | Default | Effect |
|---|---|---|
| `allow_delete: true` | `false` | Enables `delete_message` (needs `write_targets.trash`) |
| `allow_local_attachments: true` | `false` | Allows attaching local files to drafts |
| `allow_smtp: true` | `false` | Registers `send_outbound_email` and loads `smtplib` |

## Enabling outbound SMTP (opt-in)

By default ProtonBound has no send capability: `smtplib` is never imported and
`send_outbound_email` is never registered. To enable it for a workspace, add `allow_smtp:
true` to the `mail:` section:

```yaml
mail:
  permission: read-write
  allow_smtp: true
  scope:
    sources: [Folders/Outbox-Queue]
  write_targets:
    drafts: Drafts
```

When enabled the agent gets a `send_outbound_email` tool with `to`, `subject`, `body`, and
optional `cc`/`bcc` fields. The tool description instructs the agent to obtain explicit user
confirmation before calling it, since email bodies are attacker-controlled and may contain
prompt-injection instructions designed to trigger sends.

**Two independent guards prevent a hijacked agent from sending without `allow_smtp: true`:**

1. **Registration gate** — the tool is never registered when `allow_smtp: false`, so the agent
   has no knowledge of any send capability.
2. **Runtime guard** — the first line of `send_outbound_email` raises `PermissionError` if
   `allow_smtp` is `false` at call time, independent of how the function was reached.

Bridge SMTP connection settings default to `127.0.0.1:1025` and can be overridden under
`account:` with `smtp_host` / `smtp_port`.

## Inspection CLI

The `--inspect` flag launches a developer tool that shows **exactly the payloads the LLM
receives** — including `<untrusted-email-content>` fencing, defanged injection attempts, and
opaque message tokens — without routing real mail through an AI agent.

**One-shot mode** (pipe-friendly with `--raw`):

```bash
# List threads
uv run protonbound --workspace workspaces/my-clients.yaml --inspect threads --limit 5

# Search and see the fenced body payloads
uv run protonbound --workspace workspaces/my-clients.yaml --inspect search "invoice"

# View a specific message by its opaque token
uv run protonbound --workspace workspaces/my-clients.yaml --inspect message <token>

# Bare JSON for piping to jq
uv run protonbound --workspace workspaces/my-clients.yaml --inspect --raw search "q" | jq .

# Connection and session token stats
uv run protonbound --workspace workspaces/my-clients.yaml --inspect status
```

**Interactive REPL** (omit the command):

```bash
uv run protonbound --workspace workspaces/my-clients.yaml --inspect
inspect> threads
inspect> search --from alice@example.com --days 7
inspect> thread <thread_id>
inspect> message <message_id>
inspect> status
inspect> help
inspect> quit
```

Available commands mirror the MCP tool surface 1-to-1: `info`, `folders`, `threads`,
`thread`, `message`, `search`, `status`. Token IDs issued by `threads`/`search` are valid
for `thread`/`message` within the same session, subject to the same opaque-id whitelist the
LLM operates under.

## Security notes

- Workspace YAML is committed; **secrets are not**. The Bridge password is read from the OS
  keyring (preferred) or the `PROTONBOUND_BRIDGE_PASSWORD` env var — never from a config file.
  `workspaces/.gitignore` also ignores `*.secret` / `*.local.yaml`.
- Thread reconstruction stays within your allowed sources, so a thread may come back
  *partial* if some messages are outside scope — this is intentional (no peeking via All Mail).
- The scope core ([`src/protonbound/scope.py`](src/protonbound/scope.py)) is pure and fully
  unit-tested ([`tests/test_scope.py`](tests/test_scope.py)).
- **`smtplib` is only loaded when you explicitly opt in.** With the default `allow_smtp:
  false`, `smtp.py` is never imported, the send tool is never registered, and `smtplib` does
  not appear in `sys.modules`. A test enforces that no other module in the package imports it.
- **Message ids are opaque and session-scoped.** Each id encodes a mailbox index + UID + CRC;
  a tampered or guessed id is rejected before any IMAP call. Ids are also whitelisted per
  session — a tool cannot act on an id unless it was issued to the agent in the same session.
- **Email bodies are fenced as untrusted data.** `get_message` wraps the body in an explicit
  `<untrusted-email-content>` boundary, and the boundary itself is defanged if it appears in
  the message text, preventing injection through crafted content.
- **IMAP protocol injection is blocked.** Strings from the model or config that reach IMAP are
  escaped and reject CR/LF, so a value like `x\r\nA1 DELETE INBOX` is refused, not executed.
- The full threat model and the invariants it enforces are documented in
  [`SECURITY_MODEL.md`](SECURITY_MODEL.md); report vulnerabilities per
  [`SECURITY.md`](SECURITY.md).
