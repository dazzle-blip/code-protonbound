# Security Policy

ProtonBound brokers an AI agent's access to a real mailbox, so its security posture is the
point of the project. Reports of weaknesses are welcome.

## Reporting a vulnerability

Please report privately — **do not open a public issue** for a suspected vulnerability.

- Preferred: this repository's **Security → Report a vulnerability** (GitHub private security
  advisory).
- Include: affected version/commit, a description, and the smallest steps or proof-of-concept
  that demonstrate the issue.

You can expect an initial acknowledgement within a few days. Fixes for confirmed issues are
prioritised over features.

## What is in scope

Issues that break one of the invariants in [`SECURITY_MODEL.md`](SECURITY_MODEL.md), for
example:

- a path that lets the server **send mail** or open an SMTP connection;
- a way to **read or act on mail outside the configured scope** (wrong folder, wrong address,
  starred-only bypass);
- **prompt-injection** escalation — email content that causes the agent to act outside the
  documented boundaries;
- **protocol injection** (IMAP/header) via model- or message-supplied input;
- **credential exposure** beyond the documented keyring / env-var handling;
- **path traversal / local-file exfiltration** via attachments.

## What is out of scope

- A human deliberately approving and sending a draft ProtonBound prepared (it cannot send;
  the human does, in Proton).
- Compromise of the host, the Proton Bridge process, or the OS keyring backend.
- Capabilities of *other* tools in a multi-tool agent (ProtonBound does not control sibling
  filesystem/shell tools; see the residual-risks section of the model).
- Denial of service from pointing scope at an enormous mailbox (bounded, not eliminated).

## Supported versions

ProtonBound is pre-1.0; only the latest `main` is supported. Pin to a commit you have
reviewed.
