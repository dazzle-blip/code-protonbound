"""Deterministic scope enforcement — the security core.

This module is intentionally pure (no I/O, no IMAP, no network) so the whole access
model can be unit-tested in isolation. Every read returned by the server and every
mailbox a tool touches is gated here.

Model: scope is **deny-by-default** with **combination (AND)** semantics. A message is
in scope only if all of the following hold:

1. it lives in an allowed *source* mailbox (``scope.sources``);
2. if ``scope.require_starred`` is set, it is starred (IMAP ``\\Flagged``);
3. if ``scope.addresses`` is non-empty, one of those addresses appears in the message's
   From/To/Cc **or** its delivery headers (Delivered-To / X-Original-To / Envelope-To).

Step 3's delivery-header check is what makes BCC work: a BCC'd message has no ``Bcc``
header and shows ``To: Undisclosed Recipients``, but Proton records the receiving alias
in the delivery headers.
"""

from __future__ import annotations

from collections.abc import Iterable

from .config import MailConfig, ScopeConfig

#: Headers (lower-cased) that reveal the true recipient of a BCC'd message.
DELIVERY_HEADERS: tuple[str, ...] = ("delivered-to", "x-original-to", "envelope-to")


class ScopeError(Exception):
    """Raised when a tool attempts something outside the workspace's configured scope."""


def normalize_address(address: str) -> str:
    """Lower-case an address and drop ``+tag`` sub-addressing for comparison.

    ``Me+Project@Proton.me`` and ``me@proton.me`` are the same Proton mailbox, so we
    compare on the base address. Display names are expected to be stripped by the caller
    (use :func:`email.utils.getaddresses`).
    """

    address = address.strip().lower()
    if "@" not in address:
        return address
    local, _, domain = address.partition("@")
    local = local.split("+", 1)[0]
    return f"{local}@{domain}"


def _normalized_set(addresses: Iterable[str]) -> set[str]:
    return {normalize_address(a) for a in addresses if a and "@" in a}


def is_source_allowed(mailbox: str, scope: ScopeConfig) -> bool:
    """Whether ``mailbox`` is one of the configured source mailboxes (exact match)."""

    return mailbox in set(scope.sources)


def allowed_sources(all_mailboxes: Iterable[str], scope: ScopeConfig) -> set[str]:
    """The readable source mailboxes that actually exist on the server.

    Deny-by-default: the result is the intersection of the configured allow-list with the
    mailboxes the server reports, so it is empty when nothing is configured.
    """

    available = set(all_mailboxes)
    return {source for source in scope.sources if source in available}


def address_allowed(message_addresses: Iterable[str], scope: ScopeConfig) -> bool:
    """Whether the message satisfies the address allow-list.

    ``message_addresses`` must already include addresses gathered from From/To/Cc *and*
    the delivery headers. Returns ``True`` when no address allow-list is configured.
    """

    if not scope.addresses:
        return True
    allowed = _normalized_set(scope.addresses)
    present = _normalized_set(message_addresses)
    return bool(allowed & present)


def message_in_scope(
    mailbox: str,
    message_addresses: Iterable[str],
    is_starred: bool,
    scope: ScopeConfig,
) -> bool:
    """The AND combiner applied to every fetched message."""

    if not is_source_allowed(mailbox, scope):
        return False
    if scope.require_starred and not is_starred:
        return False
    return address_allowed(message_addresses, scope)


def assert_source_in_scope(mailbox: str, scope: ScopeConfig) -> None:
    """Guard called by every read tool before selecting a mailbox."""

    if not is_source_allowed(mailbox, scope):
        raise ScopeError(
            f"Mailbox {mailbox!r} is not in this workspace's scope. "
            f"Allowed sources: {sorted(scope.sources)}"
        )


def resolve_write_target(name: str, mail: MailConfig) -> str:
    """Resolve a named write target (e.g. ``'drafts'``) to its real mailbox name.

    Write targets are resolved *only* from ``write_targets`` and are never read scope —
    a draft destination does not become readable by the agent.
    """

    value = getattr(mail.write_targets, name, None)
    if not value:
        raise ScopeError(f"No write target configured for {name!r} in this workspace")
    return value
