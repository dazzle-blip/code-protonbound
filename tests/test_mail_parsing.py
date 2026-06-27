"""Unit tests for IMAP FETCH-response parsing (no network).

These pin the exact wire shapes imaplib hands back, including the Proton Bridge layout
that emits ``UID`` *after* the body literal — which imaplib returns as a separate,
non-tuple list element. Before this was handled, every message was silently dropped and
``list_threads`` came back empty against a real Bridge.
"""

from __future__ import annotations

import email

from protonbound.mail import _date_key, _extract_text, _parse_fetch, _reply_recipients

_HDR = (
    b'From: "improv-team" <noreply@example.com>\r\n'
    b"To: <team@example.com>\r\n"
    b"Cc: producer@club.example\r\n"
    b"Subject: Gig enquiry\r\n"
    b"Message-ID: <abc@example>\r\n"
    b"Delivered-To: team@example.com\r\n"
    b"\r\n"
)

# A Proton/SimpleLogin alias message: From is the real sender, Reply-To is the reverse
# forwarder, To is the user's alias.
_ALIAS_HDR = (
    b'From: "Tutor Hunt" <sender@example.com>\r\n'
    b'Reply-To: "Tutor Hunt" <sender-fwd@example.com>\r\n'
    b"To: <you-alias@example.com>\r\n"
    b"Subject: Welcome\r\n"
    b"Message-ID: <sl1@example>\r\n"
    b"\r\n"
)

BOX = "Folders/Work/Demo"


def test_uid_after_body_literal_is_parsed():
    """Proton Bridge layout: `UID n)` arrives as the element *after* the body tuple."""

    data = [
        (b"1 (FLAGS (\\Flagged \\Seen) BODY[HEADER.FIELDS (FROM TO CC SUBJECT)] {123}", _HDR),
        b" UID 7)",
    ]
    headers = _parse_fetch(BOX, data)

    assert len(headers) == 1
    h = headers[0]
    assert h.uid == "7"
    assert h.from_addr == "noreply@example.com"
    assert h.to == ["team@example.com"]
    assert h.cc == ["producer@club.example"]
    assert "team@example.com" in h.delivery
    assert h.is_starred is True  # \Flagged was present


def test_uid_inline_before_body_still_parsed():
    """Servers that put `UID n` in the prefix (before the literal) must still work."""

    data = [
        (b"2 (UID 9 FLAGS (\\Seen) BODY[HEADER.FIELDS (FROM TO SUBJECT)] {123}", _HDR),
        b")",
    ]
    headers = _parse_fetch(BOX, data)

    assert len(headers) == 1
    assert headers[0].uid == "9"
    assert headers[0].is_starred is False


def test_each_message_folds_in_its_own_trailing_uid():
    """A multi-message response must pair each body with its own trailing `UID`."""

    data = [
        (b"1 (FLAGS (\\Seen) BODY[HEADER.FIELDS (FROM TO SUBJECT)] {123}", _HDR),
        b" UID 4)",
        (b"2 (FLAGS () BODY[HEADER.FIELDS (FROM TO SUBJECT)] {123}", _HDR),
        b" UID 5)",
    ]
    headers = _parse_fetch(BOX, data)

    assert [h.uid for h in headers] == ["4", "5"]
    assert headers[0].is_starred is False
    assert headers[1].is_starred is False


# -- reply addressing: honour the alias reverse forwarder -----------------------------


def test_reply_to_header_is_captured():
    data = [
        (b"1 (FLAGS () BODY[HEADER.FIELDS (FROM REPLY-TO TO SUBJECT)] {180}", _ALIAS_HDR),
        b" UID 1)",
    ]
    h = _parse_fetch(BOX, data)[0]
    assert h.from_addr == "sender@example.com"
    assert h.reply_to == ["sender-fwd@example.com"]


def test_reply_goes_to_reverse_forwarder_when_reply_to_present():
    """Alias mail: reply must target the Reply-To reverse forwarder, not the real From."""

    targets = _reply_recipients(
        ["sender-fwd@example.com"], "sender@example.com"
    )
    assert targets == ["sender-fwd@example.com"]


def test_reply_falls_back_to_from_without_reply_to():
    assert _reply_recipients([], "real-sender@example.com") == ["real-sender@example.com"]
    # display-name form is reduced to the bare address
    assert _reply_recipients([], '"Bob" <bob@example.com>') == ["bob@example.com"]


# -- chronological ordering (not lexicographic on the raw Date string) -----------------


def test_date_key_orders_chronologically_across_weekdays():
    # Raw-string sort would order these by weekday name ("Fri" < "Mon" < "Sat" < "Sun");
    # _date_key must order them by actual time instead.
    dates = [
        "Fri, 19 Jun 2026 13:03:08 +0000",  # newest
        "Mon, 22 Mar 2025 17:52:36 +0000",
        "Sat, 20 Sep 2022 19:40:29 +0000",  # oldest
    ]
    newest_first = sorted(dates, key=_date_key, reverse=True)
    assert newest_first == [
        "Fri, 19 Jun 2026 13:03:08 +0000",
        "Mon, 22 Mar 2025 17:52:36 +0000",
        "Sat, 20 Sep 2022 19:40:29 +0000",
    ]


def test_date_key_handles_naive_and_unparseable():
    # naive (no offset) is comparable to tz-aware; junk sorts oldest
    assert _date_key("Wed, 1 Jan 2025 00:00:00") > _date_key("not a date")
    assert _date_key("") == _date_key("garbage")


# -- body extraction: HTML -> Markdown (formatting preserved) --------------------------


def test_html_body_is_converted_to_markdown():
    """HTML emphasis survives as Markdown rather than being flattened to plain text."""
    raw = (
        b"Content-Type: multipart/alternative; boundary=B\r\n\r\n"
        b"--B\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body><style>.x{color:red}</style>"
        b"<h1>Hi</h1><p>Hello <b>there</b></p>Line two</body></html>\r\n"
        b"--B--\r\n"
    )
    body = _extract_text(email.message_from_bytes(raw))
    assert "Hello **there**" in body  # bold preserved as Markdown
    assert "Line two" in body
    assert "<" not in body  # tags converted
    assert "color:red" not in body  # <style> contents dropped


def test_html_alternative_is_preferred_for_formatting():
    """When both parts exist, prefer HTML->Markdown so emphasis isn't lost to plain text."""
    raw = (
        b"Content-Type: multipart/alternative; boundary=B\r\n\r\n"
        b"--B\r\n"
        b"Content-Type: text/plain\r\n\r\nplain version\r\n"
        b"--B\r\n"
        b"Content-Type: text/html\r\n\r\n<p>rich <b>bold</b></p>\r\n"
        b"--B--\r\n"
    )
    assert _extract_text(email.message_from_bytes(raw)) == "rich **bold**"


def test_plain_only_message_unchanged():
    raw = b"Content-Type: text/plain\r\n\r\njust plain text\r\n"
    assert _extract_text(email.message_from_bytes(raw)).strip() == "just plain text"


def test_single_part_html_is_converted_to_markdown():
    raw = b"Content-Type: text/html; charset=utf-8\r\n\r\n<p>Single &amp; only</p>\r\n"
    assert _extract_text(email.message_from_bytes(raw)) == "Single & only"
