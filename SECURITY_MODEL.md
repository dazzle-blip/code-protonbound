# ProtonBound Security Model

An auditable map of **what ProtonBound guarantees, how, and what it does not**. It exists
because the server hands an LLM access to a real mailbox, and email is attacker-controlled
input.

## Threat model

The primary adversary is **indirect prompt injection**: every message body, subject, and
sender string is text an outsider chose, and an agent reading your mail can be steered by a
malicious message into misusing its tools. Secondary concerns are **scope escape** (touching
mail the workspace shouldn't see), **protocol injection** (IMAP/header), **credential
exposure**, and **local-file exfiltration**.

The design goal is therefore not "trust the model" but **bound what a fully-hijacked agent
can do**, so that the worst case is small and recoverable.

## Trust boundaries

| Party | Trusted? |
|---|---|
| The workspace owner editing YAML / running the CLI | Trusted (sets the policy) |
| The host OS, Proton Bridge, the OS keyring | Trusted (out of scope to defend) |
| The LLM / MCP client | **Untrusted** — may be hijacked by injected content |
| Email content (bodies, subjects, senders, attachments) | **Untrusted** — passive data only |

## Enforced invariants

Each is enforced in code, not by prompting.

### 1. The server cannot send mail unless the owner opts in — and is structurally blind to sending otherwise
By default (`allow_smtp: false`) no send tool is registered and `smtplib` is never imported:
the agent has no knowledge of any send capability and a hijacked agent's worst outcome is a
**draft the human reviews**, never mail that left the machine. Sending is a deliberate,
launch-time opt-in the agent cannot reach over MCP (`allow_smtp: true`), which is the *only*
condition under which `send_outbound_email` is registered and `smtp.py` — the sole module that
touches `smtplib` — is lazily imported. Even then a runtime `PermissionError` guard is the
first line of the send function, so the boundary holds even if a future refactor broke the
registration gate. When enabled, the SMTP transport pins Bridge's TLS cert after STARTTLS and
fails closed before credentials are sent (see #9).
*Where:* `src/protonbound/server.py` (conditional `send_outbound_email` registration + in-function guard); `src/protonbound/smtp.py` (lazy `smtplib`, cert pin); `tests/test_tool_surface.py::test_only_smtp_module_imports_smtplib`, `::test_smtplib_not_loaded_with_smtp_disabled`, `::test_send_runtime_guard_raises_if_smtp_disabled`.

### 2. Reads and writes are deny-by-default scoped
A message is in scope only if it lives in an allowed source mailbox **and** (if configured)
matches the address allow-list **and** (if `require_starred`) is starred. Every id-addressed
operation re-checks scope before issuing an IMAP command.
*Where:* `src/protonbound/scope.py` (`message_in_scope`, `assert_source_in_scope`);
re-checked in `get_message`, `draft_reply`, `move_message`, `apply_label`, etc.

### 3. Capabilities are absent unless enabled
Write tools exist only in `read-write` workspaces; `delete_message` only when `allow_delete`;
local-file attachments only when `allow_local_attachments`. A disabled capability is **not in
the tool schema**, so the model cannot call it — and the toggles live in launch-time config
the agent cannot reach over MCP.
*Where:* `src/protonbound/server.py` (conditional `@mcp.tool()` registration).

### 4. Message ids are opaque, integrity-checked, and unforgeable-by-guessing
Ids encode a mailbox **index + UID + CRC**, base64url. Decoding validates the UID is numeric,
the index is in range, and the CRC matches — so sequential-id guessing or a tampered token is
rejected before any IMAP call, and a stale id from a changed mailbox set fails loudly instead
of resolving to the wrong box. In addition, a **session whitelist** records only the ids
actually handed back by a list/thread/search pass, and every by-id tool rejects an id that
isn't on it — so an id must be *obtained*, not guessed or reused across sessions.
*Where:* `src/protonbound/mail.py` (`_MailboxIndex.encode`/`decode`, `_issue`/`_require_issued`).

### 5. Email bodies are fenced as untrusted data
`get_message` wraps the body in an explicit `<untrusted-email-content>` boundary with a
security note, and defangs any attempt by the body to forge that boundary. The destructive
tool's description tells the agent to get human confirmation if a deletion was *suggested by
email content*.
*Where:* `src/protonbound/mail.py` (`_wrap_untrusted_body`); `delete_message` description in `server.py`.

### 6. Protocol injection is blocked
Model- and config-supplied strings that reach IMAP are escaped and **reject CR/LF**: mailbox
names (`_quote_mailbox`), the `from_addr` search term, and the numeric-UID check. So a value
like `x@y"\r\nA1 DELETE INBOX` is refused, not executed.
*Where:* `src/protonbound/mail.py` (`_imap_quoted`, `_search_criteria`, `_MailboxIndex.decode`).

### 7. Reads never mutate mailbox state
Every fetch uses IMAP `BODY.PEEK[...]`, so reading does not clear the unread flag.
*Where:* `src/protonbound/mail.py` (`_fetch_message`, `_fetch_headers`).

### 8. No local-filesystem or shell surface
The MCP schema exposes mail tools only — no `exec`/`eval`, shell, or directory-navigation
tools. Outgoing attachments default to **re-attaching files already on in-scope mail**;
reading an arbitrary **local file** is an explicit opt-in (`allow_local_attachments`) with a
size cap (`max_attachment_mb`).
*Where:* `src/protonbound/server.py` tool list; `mail.py` (`_resolve_attachment`).

### 9. Secrets stay out of the repo, and the Bridge channel can be cert-pinned
The Bridge password is read from the **OS keyring** (preferred) or the
`PROTONBOUND_BRIDGE_PASSWORD` env var — never from a committed file. Both transports use
STARTTLS over the loopback; when `account.bridge_cert_sha256` is set, the presented cert is
pinned and the connection **fails closed before credentials are sent** on mismatch — on the
IMAP read path and, when `allow_smtp` is enabled, on the SMTP send path too. This defeats a
local TLS-interception proxy on the loopback. The fingerprint is captured with
`protonbound --show-cert`.
*Where:* `src/protonbound/server.py` (`_password_provider`); `__main__.py` (`--set-password`); `mail.py` (`_verify_pinned_cert`, IMAP); `smtp.py` (`_verify_pinned_cert`, SMTP).

### 10. One workspace per process
Each server instance binds exactly one workspace, so the "career" agent cannot reach "comedy"
mail — isolation is structural, not policy.
*Where:* `src/protonbound/__main__.py`.

## Residual risks (non-goals)

ProtonBound deliberately does **not** defend against these:

- **A human acting on a malicious draft.** In the default no-send posture the agent can only
  draft; if the human reviews a poisoned draft and clicks Send in Proton, that's outside the
  boundary. The fence (#5) and the draft-disclosure of recipients/attachments exist to make
  that review meaningful.
- **A human approving a malicious send.** When `allow_smtp: true`, the send tool's description
  requires explicit human confirmation of recipient and content, but that confirmation is a
  prompt-level mitigation, not a code-enforced one — a human who confirms a poisoned send is
  outside the boundary. Enable `allow_smtp` only where supervised sending is intended.
- **A multi-tool agent.** If the same agent also holds shell/filesystem tools, those can stage
  files or exfiltrate independently of ProtonBound. With `allow_smtp: false` (default),
  ProtonBound contributes no send capability, so it only becomes an *autonomous* exfiltration
  path if a sibling tool can send; with `allow_smtp: true` ProtonBound itself is that path,
  gated only by the human-confirmation prompt.
- **Host / Bridge / keyring compromise.** A compromised machine or Bridge process is game over;
  ProtonBound trusts them.
- **Availability under huge scope.** `_MAX_SCAN_PER_SOURCE` bounds work, which can drop the
  oldest mail from a giant folder — a confidentiality-preserving cap, not an availability
  guarantee.

## Configuration that changes the posture

| Setting | Effect when enabled |
|---|---|
| `permission: read-write` | adds drafting + housekeeping tools (still no send) |
| `allow_smtp` | registers `send_outbound_email` and imports `smtplib`; the agent can send via Bridge (human-supervised). Pin `bridge_cert_sha256` when enabling |
| `allow_delete` | adds `delete_message` (move to Trash) |
| `allow_local_attachments` | lets drafts read arbitrary local files (size-capped) |
| `require_starred` | narrows scope to starred messages only |
| `scope.addresses` | narrows scope to mail involving those addresses (incl. BCC) |

Defaults are the conservative choice in every case.
