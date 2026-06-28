# Getting started with ProtonBound

This guide takes you from a clean checkout to a registered MCP server: install,
configure a workspace, store the Bridge password, optionally pin Bridge's TLS
certificate, enable sending, and register the server with your MCP client. For *why*
the design works the way it does, see [`README.md`](README.md) and the full threat
model in [`SECURITY_MODEL.md`](SECURITY_MODEL.md).

> ProtonBound is tailored to **Proton Mail via Proton Bridge**, but Bridge simply
> exposes mail over local **IMAP/SMTP** — the same configuration works against any
> IMAP/SMTP provider. The steps below assume Bridge; substitute your provider's host,
> port, username and password where noted.

## 1. Prerequisites

1. **Proton Bridge** installed, running, and signed in. Add your account and note the
   per-account **IMAP username** and **Bridge password** (Bridge → account → *Mailbox
   configuration*). This is the Bridge password, **not** your Proton login password.
2. **Python 3.11+** and [**uv**](https://docs.astral.sh/uv/).

## 2. Install

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

## 3. Configure a workspace

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
permission tier, and the real names of your Drafts/Trash mailboxes as Bridge reports
them. See [`workspaces/example-clients.yaml`](workspaces/example-clients.yaml) for a
fully commented example. One server instance serves exactly one workspace.

**Account options** (all under `account:`):

| Field | Default | Description |
|---|---|---|
| `username` | *(required)* | Bridge IMAP/SMTP login — your primary Proton address |
| `imap_host` | `127.0.0.1` | Bridge host |
| `imap_port` | `1143` | Bridge IMAP port |
| `smtp_host` | `127.0.0.1` | Bridge SMTP host (used only when `allow_smtp: true`) |
| `smtp_port` | `1025` | Bridge SMTP port (used only when `allow_smtp: true`) |
| `from_address` | same as `username` | Sender identity for drafts and outbound mail (use to send *as* an alias) |
| `bridge_cert_sha256` | *(unset)* | SHA-256 fingerprint to pin Bridge's TLS cert (see [§5](#5-pin-the-bridge-tls-certificate-optional-but-recommended)) |

### How scope works

Each *workspace* is a single committed YAML file, `workspaces/<name>.yaml`
(name/description/account plus a `mail:` section for permission, scope, and write
targets). Scope is **deny-by-default** and combines (AND) up to three filters — a
message is in scope only if **all** apply:

1. it is in an allowed **source** mailbox (`scope.sources`);
2. if `require_starred: true`, it is **starred**;
3. if `scope.addresses` is set, one of those addresses appears in From/To/Cc **or** the
   delivery headers (`Delivered-To` / `X-Original-To` / `Envelope-To` — this is how
   BCC'd mail to your aliases is matched).

## 4. Store the Bridge password

Preferred — keep the secret in your **OS keyring** (Windows Credential Manager / macOS
Keychain / Linux Secret Service), keyed by the workspace's IMAP username:

```bash
uv run protonbound --set-password --workspace workspaces/my-clients.yaml
# prompts for the Bridge password and stores it; never written to a file or env var
```

At runtime the server reads the keyring first and falls back to the
`PROTONBOUND_BRIDGE_PASSWORD` environment variable if the keyring has no entry — so the
env var still works for headless/CI use where no keyring backend exists.

## 5. Pin the Bridge TLS certificate (optional but recommended)

Proton Bridge listens on localhost with a self-signed TLS certificate. Pinning it by
SHA-256 fingerprint means the server will refuse to connect — and therefore refuse to
send your credentials — if Bridge ever presents a different certificate (e.g. due to a
local TLS interception proxy).

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

On the next launch the server validates the cert before authenticating. If it
mismatches, the connection is aborted with a clear error. The same fingerprint pins
**both** transports: the IMAP read connection and — when `allow_smtp: true` — the SMTP
send connection, which is checked after STARTTLS and fails closed before your Bridge
password is transmitted.

## 6. Choose a permission tier and tool surface

| `permission` | Reads | Drafts & housekeeping | Sends |
|--------------|:-----:|:---------------------:|:-----:|
| `readonly`   | ✅    | ❌                    | ❌ by default |
| `read-write` | ✅    | ✅                    | ❌ by default |

This table shows what each tier **permits**, not what is exposed. The actual tool
surface is deny-first: a tool appears only if it is listed in `tools:` *and* its
tier/flag prerequisite is met (see [the `tools:` allow-list](#the-exact-tool-surface-is-declared-by-tools-deny-first) below).

Sending is a separate opt-in flag, independent of the permission tier:

| `mail:` flag | Default | Effect |
|---|---|---|
| `allow_delete: true` | `false` | Enables `delete_message` (needs `write_targets.trash`) |
| `allow_local_attachments: true` | `false` | Allows attaching local files to drafts |
| `allow_smtp: true` | `false` | Registers `send_draft` and loads `smtplib` |

### The exact tool surface is declared by `tools:` (deny-first)

The set of tools exposed to the model is **deny-first**: it is exactly the `tools:`
list and nothing else — not even `get_workspace_info` unless you list it. The field
defaults to an empty list, so a workspace that names no tools exposes none (the safe
default).

```yaml
mail:
  permission: read-write
  allow_smtp: true
  scope:
    sources: [Folders/Outbox-Queue]
  write_targets:
    drafts: Drafts
  tools:                 # the surface is exactly these four tools
    - list_threads
    - get_thread
    - draft_reply
    - send_draft
```

The list **narrows; it never grants.** A tool may be listed only if its prerequisite is
enabled — write tools need `permission: read-write`, `delete_message` needs
`allow_delete`, `send_draft` needs `allow_smtp` — and the config fails to load otherwise
(an unknown tool name is rejected too, so a typo fails loudly). So the exposed surface
is always `(tier/flag-permitted) ∩ (tools list)`: the capability gates still apply, and
the list picks which permitted tools the model actually sees. The committed
`workspaces/example-clients.yaml` lists the full read + draft/housekeeping surface as a
starting point — trim it to expose less.

## 7. Enabling outbound SMTP (opt-in)

By default ProtonBound has no send capability: `smtplib` is never imported and
`send_draft` is never registered. To enable it for a workspace, add `allow_smtp: true`
to the `mail:` section:

```yaml
mail:
  permission: read-write
  allow_smtp: true
  scope:
    sources: [Folders/Outbox-Queue]
  write_targets:
    drafts: Drafts
```

When enabled the agent gets a single send tool, **`send_draft`**, which takes **only an
opaque `draft_id`** — there is deliberately no content-taking send tool. Sending is the
second stage of a two-step, draft-first flow:

1. Compose with `save_draft` / `draft_reply` / `update_draft`. The message lands in
   **Drafts**, where the user can review it in their normal Proton client.
2. Call `send_draft(draft_id)` to send **exactly that draft**, byte-for-byte. There is
   no `to`/`body` parameter to divert, so what goes out is what was reviewed. On success
   the draft is removed from Drafts (Proton stores the Sent copy server-side).

Because `send_draft` only references an existing draft by id, a prompt-injection cannot
smuggle an arbitrary recipient or body through the send call itself — it can at most send
a draft that already exists and is visible for review. The tool description also
instructs the agent to obtain explicit user confirmation before calling it. `Bcc`
recipients saved on the draft are honoured (they receive the mail) but the `Bcc` header
is stripped from the transmitted message, as normal for a sent email.

**Two independent guards prevent a hijacked agent from sending without `allow_smtp: true`:**

1. **Registration gate** — the tool is never registered when `allow_smtp: false`, so the
   agent has no knowledge of any send capability.
2. **Runtime guard** — the first line of `send_draft` raises `PermissionError` if
   `allow_smtp` is `false` at call time, independent of how the function was reached.

Bridge SMTP connection settings default to `127.0.0.1:1025` and can be overridden under
`account:` with `smtp_host` / `smtp_port`.

### The sender is bound to the workspace's scope

A send-enabled workspace can only send **as one of its own in-scope addresses**. When
`scope.addresses` is set, the configured sender (`account.from_address`, else
`username`) must be one of those aliases — this is checked at launch (the workspace fails
to load otherwise) and **re-checked at the moment of each send**. So a `career` workspace
cannot send from a `comedy` alias even if hijacked, and the model has no parameter to
override the sender. With no `scope.addresses` configured there is nothing to bind
against, so the single configured identity is used unrestricted.

### Hard kill-switch: delete the send module

For a guarantee that doesn't depend on config at all, **delete the send module**:

```bash
rm src/protonbound/smtp.py
```

`smtp.py` is the *only* file in the package that imports `smtplib`. With it gone there is
no send code to run, so sending is structurally impossible regardless of any `allow_smtp`
setting — a stronger statement than a config flag, since it can't be flipped back by
editing YAML.

The server is built to treat this as a supported state, not a crash:

- At startup it checks for the module with `importlib.util.find_spec` — which *locates*
  without *importing*, so the check itself never pulls in `smtplib`. If the module is
  absent, the server runs **exactly as if `allow_smtp: false`**: the send tool is not
  registered, the agent-facing instructions say it can never send, and
  `get_workspace_info` reports `can_send: false`.
- If a workspace still has `allow_smtp: true` while the module is gone, the server starts
  normally and prints a one-line notice on **stderr** explaining that sending is disabled.
- If the file is removed *while the server is running*, an attempted send fails closed
  with a clear `PermissionError` rather than a raw `ModuleNotFoundError`.

To restore sending, put `smtp.py` back (e.g. `git checkout -- src/protonbound/smtp.py`)
and restart. This makes a third, **physical** layer beneath the registration gate and
runtime guard above.

## 8. Signatures

Proton applies your account signature only when you compose in a Proton client; **Bridge
does not add it** to mail composed through IMAP/SMTP here. So define a signature per
workspace if you want one:

```yaml
mail:
  signature: |
    Jane Doe
    Acme Co — contact@example.com
```

When set, `draft_reply` / `save_draft` / `update_draft` take an `append_signature` flag
(default **true**) that appends it below the body under the RFC 3676 `-- ` delimiter.
(`send_draft` needs no such flag — it sends a draft whose signature was already applied
when it was composed.) The text is added **verbatim by code** — the model never authors
or edits the signature, it only chooses whether to include it (e.g. omitting it on a
terse internal reply). With no `signature` configured the flag is a no-op.

## 9. Try it locally with the MCP Inspector

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

## 10. Register with an MCP client

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

> On Windows, use the absolute path to the workspace and ensure `uv` is on `PATH` (or
> give the full path to `uv.exe`). Bridge's default ports (IMAP 1143) are identical on
> both OSes.

## 11. Inspection CLI

The `--inspect` flag launches a developer tool that shows **exactly the payloads the LLM
receives** — including `<untrusted-email-content>` fencing, defanged injection attempts,
and opaque message tokens — without routing real mail through an AI agent.

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
`thread`, `message`, `search`, `status`. Token IDs issued by `threads`/`search` are
valid for `thread`/`message` within the same session, subject to the same opaque-id
whitelist the LLM operates under.
