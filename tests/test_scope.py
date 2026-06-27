"""Unit tests for the deterministic scope core (no network)."""

from __future__ import annotations

import pytest

from protonbound.config import ScopeConfig
from protonbound.scope import (
    ScopeError,
    address_allowed,
    allowed_sources,
    assert_sendable_from,
    assert_source_in_scope,
    is_source_allowed,
    message_in_scope,
    normalize_address,
    sendable_from_addresses,
)


def make_scope(**kwargs) -> ScopeConfig:
    kwargs.setdefault("sources", ["Labels/AI", "Folders/Clients"])
    return ScopeConfig(**kwargs)


# -- source allow-list ----------------------------------------------------------------


def test_allowed_sources_is_intersection_with_existing():
    scope = make_scope()
    existing = ["INBOX", "Labels/AI", "Spam"]  # Folders/Clients does not exist here
    assert allowed_sources(existing, scope) == {"Labels/AI"}


def test_out_of_scope_mailbox_is_rejected():
    scope = make_scope()
    assert is_source_allowed("Labels/AI", scope)
    assert not is_source_allowed("INBOX", scope)
    with pytest.raises(ScopeError):
        assert_source_in_scope("INBOX", scope)


# -- sendable-from restriction --------------------------------------------------------


def test_sendable_from_restricted_to_scope_addresses():
    scope = make_scope(addresses=["alias@proton.me", "Other+tag@Proton.me"])
    allowed = sendable_from_addresses(scope, "me@proton.me")
    assert allowed == {"alias@proton.me", "other@proton.me"}  # normalised, +tag dropped
    # an in-scope alias is fine; the primary login (out of scope) is refused
    assert_sendable_from("ALIAS@proton.me", scope, "me@proton.me")
    with pytest.raises(ScopeError, match="only send from its in-scope"):
        assert_sendable_from("me@proton.me", scope, "me@proton.me")


def test_sendable_from_unrestricted_without_addresses():
    scope = make_scope(addresses=[])
    # with no scope.addresses, only the single configured identity is sendable (no-op gate)
    assert sendable_from_addresses(scope, "me@proton.me") == {"me@proton.me"}
    assert_sendable_from("me@proton.me", scope, "me@proton.me")
    with pytest.raises(ScopeError):
        assert_sendable_from("someone-else@proton.me", scope, "me@proton.me")


# -- address allow-list ---------------------------------------------------------------


def test_empty_address_allowlist_matches_any():
    scope = make_scope(addresses=[])
    assert address_allowed(["random@elsewhere.com"], scope) is True


def test_address_allowlist_filters():
    scope = make_scope(addresses=["me@proton.me"])
    assert address_allowed(["me@proton.me", "x@y.com"], scope) is True
    assert address_allowed(["x@y.com"], scope) is False


def test_address_match_is_case_insensitive_and_ignores_subaddressing():
    scope = make_scope(addresses=["me@proton.me"])
    assert normalize_address("Me+Clients@Proton.me") == "me@proton.me"
    assert address_allowed(["Me+Clients@Proton.me"], scope) is True


# -- require_starred curation gate ----------------------------------------------------


def test_require_starred_gate():
    scope = make_scope(require_starred=True, addresses=[])
    # starred passes
    assert message_in_scope("Labels/AI", ["a@b.com"], True, scope) is True
    # unstarred in the same source is excluded
    assert message_in_scope("Labels/AI", ["a@b.com"], False, scope) is False


def test_require_starred_ignored_when_false():
    scope = make_scope(require_starred=False, addresses=[])
    assert message_in_scope("Labels/AI", ["a@b.com"], False, scope) is True


# -- AND combiner ---------------------------------------------------------------------


def test_combiner_requires_source_and_address():
    scope = make_scope(addresses=["me@proton.me"])
    # right source, right address
    assert message_in_scope("Labels/AI", ["me@proton.me"], False, scope) is True
    # right source, wrong address
    assert message_in_scope("Labels/AI", ["nope@x.com"], False, scope) is False
    # wrong source, right address
    assert message_in_scope("INBOX", ["me@proton.me"], False, scope) is False


# -- BCC handling ---------------------------------------------------------------------


def test_bcc_message_matches_via_delivery_header():
    """An alias appearing only in delivery headers (BCC) is still in scope."""

    scope = make_scope(addresses=["alias@pm.me"])
    # To is "undisclosed"; the alias only shows up in Delivered-To, included in the
    # combined scope_addresses list the caller passes in.
    combined = ["sender@external.com", "alias@pm.me"]  # last entry came from Delivered-To
    assert message_in_scope("Folders/Clients", combined, False, scope) is True


def test_bcc_to_unlisted_alias_is_out_of_scope():
    scope = make_scope(addresses=["alias@pm.me"])
    combined = ["sender@external.com", "someone-else@pm.me"]
    assert message_in_scope("Folders/Clients", combined, False, scope) is False
