"""Outbound SMTP send via Proton Bridge.

This is the *only* module in the package that imports smtplib. It is never imported
at package load time; ``server.py`` lazily imports ``send_prepared_via_bridge`` inside the
``send_draft`` tool body, which is itself only registered when the workspace sets
``allow_smtp: true``. With the default ``allow_smtp: false``, this module is never touched
and smtplib never enters sys.modules.
"""

from __future__ import annotations

import hashlib
import re
import smtplib


class SmtpError(Exception):
    """Raised when an outbound send cannot proceed safely (e.g. cert-pin mismatch)."""


def _normalize_fp(fp: str) -> str:
    """Canonicalise a cert fingerprint for comparison: lowercase hex, no colons/whitespace."""

    return re.sub(r"[\s:]", "", fp).strip().lower()


def _verify_pinned_cert(conn: smtplib.SMTP, expected: str | None) -> None:
    """Pin Proton Bridge's TLS certificate on the SMTP connection (TOFU).

    smtplib's STARTTLS, like imaplib's, accepts Bridge's self-signed cert without
    verification, so a local process could MITM the loopback — and here that loopback
    carries the Bridge *password*. When ``account.bridge_cert_sha256`` is configured we
    compare the presented cert's SHA-256 to it and fail closed BEFORE login. No-op when
    unset (mirrors the IMAP path in ``mail.py``). Capture the value with
    ``protonbound --show-cert``; the same fingerprint pins both IMAP and SMTP.
    """

    if not expected:
        return
    der = conn.sock.getpeercert(binary_form=True) if conn.sock is not None else None
    if not der:
        raise SmtpError("Proton Bridge presented no TLS certificate to pin against")
    actual = hashlib.sha256(der).hexdigest()
    if _normalize_fp(actual) != _normalize_fp(expected):
        raise SmtpError(
            "Proton Bridge SMTP certificate does not match the pinned "
            "account.bridge_cert_sha256 — refusing to send (possible interception). "
            f"Pinned {expected[:16]}…, saw {actual[:16]}…"
        )


def _deliver(
    *,
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    from_addr: str,
    recipients: list[str],
    payload: bytes,
    bridge_cert_sha256: str | None,
) -> None:
    """Run one Bridge SMTP transaction: STARTTLS, optional cert-pin, login, send.

    The single place ``smtplib`` actually transmits. When ``bridge_cert_sha256`` is set,
    Bridge's TLS cert is pinned after STARTTLS and the send fails closed — before credentials
    are transmitted — if it does not match.
    """

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as conn:
        conn.ehlo()
        conn.starttls()
        _verify_pinned_cert(conn, bridge_cert_sha256)  # fail closed BEFORE login
        conn.ehlo()
        conn.login(username, password)
        conn.sendmail(from_addr, recipients, payload)


def send_prepared_via_bridge(
    *,
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    from_addr: str,
    recipients: list[str],
    message_bytes: bytes,
    bridge_cert_sha256: str | None = None,
) -> dict:
    """Send an already-composed message (raw RFC 822 bytes) to an explicit recipient set.

    The draft-first send path: ``message_bytes`` is the user-reviewed draft exactly as it was
    stored in Drafts (minus its Bcc header), and ``recipients`` is the full To+Cc+Bcc
    envelope so blind-copied recipients still receive it. The caller is responsible for having
    stripped the Bcc header from ``message_bytes`` (the envelope here is what delivers it).
    """

    if not recipients:
        raise SmtpError("Refusing to send a draft with no recipients")
    _deliver(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        username=username,
        password=password,
        from_addr=from_addr,
        recipients=recipients,
        payload=message_bytes,
        bridge_cert_sha256=bridge_cert_sha256,
    )
    return {"sent": True, "recipients": len(recipients)}
