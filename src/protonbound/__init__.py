"""ProtonBound — a scoped, draft-only MCP server for Proton Mail via Proton Bridge.

The server NEVER sends mail and NEVER opens an SMTP connection. It can only read mail
within a deterministically enforced scope and write drafts. Scope enforcement lives in
``protonbound.scope`` (a pure, no-I/O module) and is applied to every tool call.
"""

__version__ = "0.1.0"
