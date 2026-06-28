# ProtonBound

A lightweight **MCP server** that gives an AI agent a **scoped, draft-first** view into
your Proton Mail through **Proton Bridge**.

The scope is enforced in code, not by prompting: the agent physically cannot read or
touch mail outside the workspace you configure. By default **it can never send** —
replies are saved as drafts for you to review and dispatch yourself.

> **Works with any IMAP/SMTP provider** — Bridge just exposes Proton over local
> IMAP/SMTP — but ProtonBound is **tailored to Proton + Proton Bridge** and its
> defaults assume that setup.

**New here?** Jump to **[Getting started](GETTING_STARTED.md)** for install and setup.

## Why this project

**Proton's posture, carried into the AI layer.** Proton is built on privacy-by-default,
end-to-end encryption, and minimal trust. An AI bridge into that mailbox should honour
the same posture rather than quietly undo it — so ProtonBound holds no copy of your mail,
keeps secrets out of the repo, and exposes the *minimum* surface a task needs.

**An agent reading your mail is an attack surface.** Every email body, subject, and
sender string is text an outsider chose. An agent that reads your mail can be steered by
a malicious message (*indirect prompt injection*) into misusing whatever tools it holds.
ProtonBound's design goal is not "trust the model" but to **bound what a fully-hijacked
agent can do** — so the worst case stays small and recoverable. In the default posture
that worst case is *a draft you review*, never mail that left your machine.

## What it does

- ✅ **Read** mail within a configured scope — specific folders/labels, optionally only
  starred, optionally only certain correspondents (including mail you were **BCC'd** on).
- ✅ Work **thread-centric**: list and read whole conversations.
- ✅ **Search** in-scope mail by subject/body/sender/recency/read-status.
- ✅ **Draft** replies, new messages, and **update** drafts — all saved to your Drafts.
- ✅ Optional **housekeeping**: mark read/unread, star, move/label within scope, optional delete.
- ✅ Optional **outbound SMTP send** via Bridge — off by default; opt in per workspace
  with `allow_smtp: true`. When off, `smtplib` is never imported and the send tool never
  appears, so the agent is structurally blind to sending.
- ✅ Optional **per-workspace signature**, appended by code (the model never writes it);
  when sending is enabled the sender is **restricted to the workspace's in-scope address(es)**.
- ✅ **Developer inspection CLI** (`--inspect`) — shows the exact JSON the LLM receives,
  fencing tags and opaque tokens included, without routing mail through an AI.
- ❌ No calendar, no contacts. **Mail only.**
- ❌ **No local cache or database** — every call reads from Bridge live ([why](#design)).

## How it compares

Other email MCP servers exist, both Proton-specific and generic IMAP/SMTP. The
Proton-specific ones are all **early and low-adoption** (single-digit-to-low-tens of
GitHub stars; the most-starred "Proton" one is a non-functional scaffold); the tools
people actually reach for are *generic* IMAP/SMTP servers — which work against Bridge
too. The constant across all of them is that they optimise for **capability**, and a
capability a hijacked agent holds *is* the blast radius an injected message can abuse.

ProtonBound instead competes on three axes the others mostly leave on the table — each
entry below is rated against them:

- **Scoping** — ProtonBound is deny-by-default (only the folders/addresses/starred mail
  you list) and runs one scope per process. Most others expose the **full mailbox** in a
  single multi-account process.
- **Prompt-injection defence** — ProtonBound wraps every body in an
  `<untrusted-email-content>` fence (and defangs attempts to forge that boundary) and
  hands out opaque, session-scoped message ids. Most others pass raw body text straight
  to the model.
- **Token optimisation** — ProtonBound converts HTML to Markdown and folds/de-duplicates
  quoted history, so far fewer tokens reach the model (cheaper, and a smaller surface for
  content-borne tricks). Most others return raw HTML and full quoted chains.


### Proton-specific

**[`proton-bridge-mcp`](https://github.com/miketigerblue/proton-bridge-mcp)** — closest design peer (Python, Proton Bridge).
- *Strengths:* same Python/Bridge approach; **automatic TLS cert pinning** (trust-on-
  first-use — it records Bridge's cert the first time it connects and rejects changes
  after); requires you to pass an explicit acknowledgement flag before it will delete or
  move mail.
- *Where it's weaker:* it sends over SMTP, with no draft-first with optional send step; it
  exposes the **full mailbox** with no folder/address scoping or per-process isolation
  (*scoping*); it does not fence untrusted bodies (*injection*); it returns HTML as-is
  with no Markdown/quote trimming (*tokens*). Its first-use pinning also trusts whatever
  cert is present on the first run — ProtonBound instead pins an explicit SHA-256 you
  capture and verify yourself.

**[`proton-mcp`](https://github.com/jorgenclaw/proton-mcp)** — the maximal Proton suite (Node, 36 tools, ~10★).
- *Strengths:* broadest reach by far — Mail, **Pass, Drive, Calendar, VPN** in one
  server.
- *Where it's weaker:* that breadth is the blast radius. It can read your **Pass password
  vault and TOTP** and sends directly; it has no folder/address scoping (*scoping*), no
  body fencing (*injection*), and no Markdown/quote trimming (*tokens*) — so a hijacked
  agent has far more to abuse. ProtonBound is mail-only with nothing to exfiltrate beyond
  the local Bridge password.

### Generic IMAP/SMTP (work with Bridge, not Proton-specific)

**[`mcp-email-server`](https://github.com/ai-zerolab/mcp-email-server)** — the popular baseline (Python, ~267★).
- *Strengths:* by far the most adopted; provider-agnostic; Python like ProtonBound; has
  **recipient + sender allow-lists**.
- *Where it's weaker:* it sends directly with no draft-first step; its allow-lists are
  address-only — there is **no folder-level scope or per-process isolation** (*scoping*);
  it does not fence untrusted bodies (*injection*); and it returns a flat message list
  with no HTML→Markdown or quote de-duplication (*tokens*). No cert pinning.

**[`mail-mcp`](https://github.com/tecnologicachile/mail-mcp)** — the most security-minded generic peer (Rust, ~40★).
- *Strengths:* the only other server with real defensive features — it sanitises HTML
  (ammonia) and **rejects tool-call wrapper syntax inside message bodies** (a genuine
  *injection* mitigation), uses composite stable ids, and gates deletes behind a
  confirmation flag; broad provider reach (IMAP/SMTP/EWS/Graph/OAuth2). This is the
  *fairest* comparison — ProtonBound's wins over it are real design choices, not gaps
  someone forgot to fill.
- *Where it's weaker:* it still sends directly with no draft-first boundary; it has **no
  deny-by-default folder/address scope or per-process isolation** (*scoping*); it
  *sanitises* bodies but does not *fence* them as untrusted, and it returns attachment
  content **inline by default** (*injection*); and it emits plain text plus ammonia-
  sanitised HTML, with no Markdown conversion or quote de-duplication (*tokens*). No
  explicit cert pinning. ProtonBound contains the agent rather than relying on
  sanitisation alone.

**[`email-mcp`](https://github.com/codefuturist/email-mcp)** — the feature-rich generic (Node/TS, ~65★).
- *Strengths:* the most full-featured — ~47 tools including genuine **thread
  reconstruction** (`get_thread`), a draft→send split, scheduling, templates, calendar
  extraction, and an IMAP IDLE watcher.
- *Where it's weaker:* capability over containment — direct send is available, and it has
  **no folder/address scope or per-process isolation** (*scoping*), passes message bodies
  straight to the model with no fence (*injection*), and does no HTML→Markdown or quote
  trimming (*tokens*). No cert pinning. A large surface for a hijacked agent.

**The common thread.** ProtonBound is the only one of these that is **draft-first by
default with no send capability even loaded**, **deny-by-default scoped and per-process
isolated**, **fences every body as untrusted**, and **trims HTML/quotes to cut tokens** —
while pinning Bridge's exact certificate. The others are more capable; that capability is
precisely what an injected instruction turns against you. See **[AI security](#ai-security)**.

> **Note:** this comparison of other providers was compiled with **AI assistance** from
> their public repositories and documentation (as of June 2026). Other projects move
> fast and details may be out of date or incomplete — verify against each project's own
> source before relying on these claims.

## Design

ProtonBound's choices follow from two reasons that aren't always obvious — Proton Bridge
already does some of the work, and every token handed to the model is a liability.

**No local cache — because Bridge already has one.** ProtonBound keeps no SQLite store,
no on-disk index, no mirror of your messages. Every tool call reads from Bridge live over
IMAP (a short-lived in-memory connection plus a session-only id whitelist, both discarded
when the process exits). **Proton Bridge already maintains the local cache**; a second
copy would buy nothing and create a *new copy of your mail at rest* to secure, sync, and
leak. Kill the process and no message data is left behind it. If you need caching, it
belongs in Bridge.

**HTML → Markdown — for security and token economy.** Message bodies are converted to
Markdown rather than passed as raw HTML. That strips active/structural HTML the model
doesn't need and **cuts the token count** sent to the LLM — cheaper, and a smaller
surface for content-borne tricks.

**Tuned for Proton Bridge's loopback.** Because the transport is always localhost, the
IMAP client is tuned for it: `TCP_NODELAY` and a larger `SO_RCVBUF`, a persistent
connection reused with a NOOP probe only after idle, and header-only fetches for
listings. Fast where it counts without holding mail at rest.

**Deterministic work stays out of the model.** Anything that doesn't need an LLM is done
in code, so it can't be steered:

- **Signatures** are appended verbatim by code under the RFC 3676 `-- ` delimiter — the
  model only chooses *whether* to include one, never authors it.
- **Thread folding + quote de-duplication** collapse repeated quoted history (edited
  quotes preserved) before the model ever sees the thread.
- **Attachments are forwarded, not read through the AI** — an in-scope file can be
  re-attached to a draft by reference, without its bytes ever passing into or out of the
  model. Reading attachment *content* into the LLM is a separate, size-capped opt-in.

## AI security

ProtonBound treats the LLM/MCP client as **untrusted** (it may be hijacked by injected
content) and email content as **untrusted passive data**. The controls below are enforced
in code, not by prompting. This is an overview — the full threat model and the eleven
invariants it enforces live in **[`SECURITY_MODEL.md`](SECURITY_MODEL.md)**.

### Scoping — bound what the agent can reach

- **Deny-by-default scope.** A message is in scope only if it lives in an allowed source
  mailbox **and** (if set) matches the address allow-list **and** (if `require_starred`)
  is starred. Every id-addressed operation re-checks scope before touching IMAP.
- **One workspace per process.** A `career` agent cannot reach `comedy` mail — isolation
  is structural, not policy.
- **Deny-first tool surface.** The exposed tools are exactly the workspace's `tools:`
  list and nothing implicit; the list can only *narrow* what a tier/flag already permits.
- **Draft-first, send opt-in.** With the default `allow_smtp: false` no send tool is
  registered and `smtplib` is never imported. When enabled, the sole send tool takes
  **only an opaque `draft_id`** (no recipient/body to divert) and the sender is bound to
  the workspace's own in-scope address(es).

### Malicious content — assume every message is hostile

- **Bodies are fenced** in an explicit `<untrusted-email-content>` boundary, and the
  boundary is defanged if the message tries to forge it.
- **Message ids are opaque, integrity-checked, and session-whitelisted** — guessing or
  replaying an id is rejected before any IMAP call.
- **Protocol injection is blocked** — model/config strings that reach IMAP are escaped
  and reject CR/LF, so `x\r\nA1 DELETE INBOX` is refused, not executed.
- **Nothing to exfiltrate** — no Pass/Drive integration; the only secret is the local
  Bridge password, which never leaves the machine and can't unlock your Proton account.

### Defense in depth, and the honest disclaimer

These controls shrink the blast radius; they do **not** make it zero. A sufficiently
capable agent may still be talked into misusing whatever tools it legitimately holds, and
prompt-level mitigations (e.g. "ask the human before sending") are not code-enforced. Run
`allow_smtp` only where supervised sending is intended, and review drafts before you send
them.

For an extra, OS-level layer you can **run ProtonBound as a dedicated low-privilege user**
— a separate account that has no read access to your home directory, so even a fully
hijacked process can't roam your files. You can go further and grant the package
*execute* but not broad *read* over the rest of the system. Treat this as a *calculated
risk reducer, not a guarantee*: it is unproven hardening, the exact permission semantics
(notably "execute without read") **vary by platform**, and a Python package must be
readable to be imported in the first place — so test any such setup before relying on it.

## Getting started

**Prerequisites:** Proton Bridge running and signed in, plus Python 3.11+ and
[uv](https://docs.astral.sh/uv/).

```bash
git clone <this-repo> code-protonbound
cd code-protonbound
uv sync
uv run pytest      # scope logic is pure — no Bridge needed
```

Then follow **[GETTING_STARTED.md](GETTING_STARTED.md)** to configure a workspace, store
the Bridge password, optionally pin Bridge's TLS cert, enable sending, and register the
server with your MCP client.

## Documentation

- **[GETTING_STARTED.md](GETTING_STARTED.md)** — install, configure, secrets, TLS
  pinning, sending, MCP-client registration, the inspection CLI.
- **[SECURITY_MODEL.md](SECURITY_MODEL.md)** — threat model and the enforced invariants.
- **[SECURITY.md](SECURITY.md)** — how to report a vulnerability.
- **[workspaces/example-clients.yaml](workspaces/example-clients.yaml)** — a fully
  commented example workspace.
