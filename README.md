# ProtonBound

A lightweight **MCP server** that gives an AI agent a **scoped, read-and-draft-only** view
into your Proton Mail through **Proton Bridge**.

The scope is enforced in code, not by prompting: the agent physically cannot read or touch
mail outside the workspace you configure, and **it can never send** — replies are saved as
drafts for you to review and send yourself in Proton.

## What it does (and doesn't)

- ✅ Read mail within a configured scope (specific folders/labels, optionally only starred,
  optionally only certain correspondents — including mail where you were **BCC'd**).
- ✅ Work **thread-centric**: list and read whole conversations.
- ✅ **Search** in-scope mail by subject/body/sender/recency/read-status.
- ✅ **Draft** replies, new messages, and **update** existing drafts (all saved to your Drafts).
- ✅ Optional housekeeping: mark read/unread, star, move/label within scope, optional delete.
- ❌ **No sending. No SMTP.** The server never opens an SMTP connection and has no send tool.
- ❌ No calendar, no contacts. Mail only.

> Proton Bridge exposes mail over local IMAP/SMTP only; this server uses **IMAP exclusively**.

## How it compares

Other Proton MCP servers exist. This comparison is **Proton-only and security-first**: it
ignores features that don't actually talk to Proton — e.g. `proton-mcp`'s "Calendar" is a
generic CalDAV client pointed at a self-hosted **Radicale** server on `127.0.0.1:5232`, not
Proton Calendar. Reviewed: **ProtonBound 0.1.0**, `protonmail-pro-mcp` **1.0.0**, `proton-mcp`
**1.0.0**.

| | **ProtonBound** | protonmail-pro-mcp | proton-mcp |
|---|---|---|---|
| Stack | Python | Node / TS | Node / JS |
| Proton transport | Bridge **IMAP only** | Bridge IMAP **+ remote SMTP** | Bridge IMAP + SMTP |
| **Can send mail** | **No — no SMTP, enforced by a test** | Yes | Yes |
| **Scoped access** (deny-by-default folders / addresses / starred) | **Yes** | No — full mailbox | No — full mailbox |
| **Human review before send** | **Yes — drafts only** | No — sends directly | No — sends directly |
| Destructive ops | Drafts only; delete is opt-in (→ Trash) | **Permanent delete** | Delete mail |
| Reads password vault / TOTP | **No** | No | **Yes** (`pass__get_item` / `get_totp`) |
| Credential exposure | **Local Bridge password only** | Account creds → remote SMTP | Bridge password + pass-cli |
| Attachments | Read + re-attach from in-scope mail; local-file **opt-in**, size cap | Send with attachments | Read attachments |
| Per-workspace isolation | **Yes — one scope per process** | No | No |
| **TLS cert pinning** for Bridge connection | **Yes** (`bridge_cert_sha256`) | No | No |
| **Opaque message ids** (session-scoped whitelist, CRC-verified) | **Yes** | No | No |
| **Body fencing** (untrusted content labelled, boundary defanged) | **Yes** | No | No |

**Why the security columns matter.** Every email body is attacker-controlled text, so an
agent reading your mail can be steered by a malicious message (*prompt injection*) into using
whatever tools it holds. ProtonBound is built to make a hijacked agent harmless:

- **It cannot send** — structurally (no `smtplib` anywhere in the package), not by policy. The
  worst case is a draft *you* review, never mail that left your machine.
- **Deny-by-default scope** — it only ever sees the folders/addresses you list (optionally
  starred-only), and each workspace runs as its own isolated process, so one agent can't reach
  another's mail.
- **Nothing to exfiltrate** — there is no Pass/Drive integration; the only secret is the local
  Bridge password, which never leaves your machine and can't unlock your Proton account.

The others are more capable — autonomous send, and in `proton-mcp`'s case read access to your
password vault — but that capability *is* the blast radius an injected instruction can abuse.
ProtonBound deliberately trades breadth for a tight, auditable security boundary.

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
| `username` | *(required)* | Bridge IMAP login — your primary Proton address |
| `imap_host` | `127.0.0.1` | Bridge host |
| `imap_port` | `1143` | Bridge IMAP port |
| `from_address` | same as `username` | Sender identity for new drafts (use to draft *as* an alias) |
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
| `readonly`   | ✅    | ❌                    | ❌ (never) |
| `read-write` | ✅    | ✅                    | ❌ (never) |

`delete_message` is only offered when `allow_delete: true` (and needs `write_targets.trash`).

## Security notes

- Workspace YAML is committed; **secrets are not**. The Bridge password is read from the OS
  keyring (preferred) or the `PROTONBOUND_BRIDGE_PASSWORD` env var — never from a config file.
  `workspaces/.gitignore` also ignores `*.secret` / `*.local.yaml`.
- Thread reconstruction stays within your allowed sources, so a thread may come back
  *partial* if some messages are outside scope — this is intentional (no peeking via All Mail).
- The scope core ([`src/protonbound/scope.py`](src/protonbound/scope.py)) is pure and fully
  unit-tested ([`tests/test_scope.py`](tests/test_scope.py)).
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
