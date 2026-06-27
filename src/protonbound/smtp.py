"""Outbound SMTP send via Proton Bridge.

This is the *only* module in the package that imports smtplib. It is never imported
at package load time; ``server.py`` lazily imports ``send_via_bridge`` inside the
``send_outbound_email`` tool body, which is itself only registered when the workspace
sets ``allow_smtp: true``. With the default ``allow_smtp: false``, this module is
never touched and smtplib never enters sys.modules.
"""

from __future__ import annotations

import hashlib
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


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


def send_via_bridge(
    *,
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    from_addr: str,
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    bridge_cert_sha256: str | None = None,
) -> dict:
    """Send one email via Proton Bridge SMTP.

    Only called when the workspace has ``allow_smtp: true`` and the caller has already
    verified this. The PermissionError guard in ``send_outbound_email`` (server.py) is
    the primary runtime fence; this function trusts that it has already fired.

    When ``bridge_cert_sha256`` is set, Bridge's TLS cert is pinned after STARTTLS and the
    send fails closed before credentials are transmitted if it does not match.
    """

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to
    msg["Subject"] = subject
    if cc:
        msg["Cc"] = cc
    msg.attach(MIMEText(body, "plain", "utf-8"))

    recipients = [addr.strip() for addr in to.split(",")]
    if cc:
        recipients.extend(addr.strip() for addr in cc.split(","))
    if bcc:
        recipients.extend(addr.strip() for addr in bcc.split(","))

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as conn:
        conn.ehlo()
        conn.starttls()
        _verify_pinned_cert(conn, bridge_cert_sha256)  # fail closed BEFORE login
        conn.ehlo()
        conn.login(username, password)
        conn.sendmail(from_addr, recipients, msg.as_bytes())

    return {"sent": True, "to": to, "subject": subject}
