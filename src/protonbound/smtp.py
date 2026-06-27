"""Outbound SMTP send via Proton Bridge.

This is the *only* module in the package that imports smtplib. It is never imported
at package load time; ``server.py`` lazily imports ``send_via_bridge`` inside the
``send_outbound_email`` tool body, which is itself only registered when the workspace
sets ``allow_smtp: true``. With the default ``allow_smtp: false``, this module is
never touched and smtplib never enters sys.modules.
"""

from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


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
) -> dict:
    """Send one email via Proton Bridge SMTP.

    Only called when the workspace has ``allow_smtp: true`` and the caller has already
    verified this. The PermissionError guard in ``send_outbound_email`` (server.py) is
    the primary runtime fence; this function trusts that it has already fired.
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
        conn.ehlo()
        conn.login(username, password)
        conn.sendmail(from_addr, recipients, msg.as_bytes())

    return {"sent": True, "to": to, "subject": subject}
