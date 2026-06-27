"""Outbound SMTP send: cert-pinning fails closed before credentials are transmitted."""

from __future__ import annotations

import hashlib

import pytest

from protonbound import smtp


class _FakeSock:
    def __init__(self, der: bytes) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return self._der


class _FakeSMTP:
    """Minimal stand-in for smtplib.SMTP recording the order of operations."""

    instances: list["_FakeSMTP"] = []

    def __init__(self, host: str, port: int, timeout: int | None = None) -> None:
        self.host = host
        self.port = port
        self.events: list[str] = []
        self.logged_in = False
        self.sent = False
        # The cert Bridge "presents" after STARTTLS.
        self.sock = _FakeSock(b"real-bridge-cert-bytes")
        _FakeSMTP.instances.append(self)

    def __enter__(self) -> "_FakeSMTP":
        return self

    def __exit__(self, *exc) -> None:
        return None

    def ehlo(self) -> None:
        self.events.append("ehlo")

    def starttls(self) -> None:
        self.events.append("starttls")

    def login(self, username: str, password: str) -> None:
        self.events.append("login")
        self.logged_in = True

    def sendmail(self, from_addr: str, recipients: list[str], msg: bytes) -> None:
        self.events.append("sendmail")
        self.sent = True


_REAL_FP = hashlib.sha256(b"real-bridge-cert-bytes").hexdigest()


@pytest.fixture(autouse=True)
def _patch_smtp(monkeypatch):
    _FakeSMTP.instances.clear()
    monkeypatch.setattr(smtp.smtplib, "SMTP", _FakeSMTP)


def _send(**overrides):
    kwargs = dict(
        smtp_host="127.0.0.1",
        smtp_port=1025,
        username="you@pm.me",
        password="secret",
        from_addr="you@pm.me",
        to="dest@example.com",
        subject="hi",
        body="hello",
    )
    kwargs.update(overrides)
    return smtp.send_via_bridge(**kwargs)


def test_send_succeeds_with_no_pin():
    result = _send()
    assert result["sent"] is True
    assert _FakeSMTP.instances[0].sent is True


def test_send_succeeds_when_pin_matches():
    result = _send(bridge_cert_sha256=_REAL_FP)
    assert result["sent"] is True
    assert _FakeSMTP.instances[0].logged_in is True


def test_send_succeeds_with_colon_formatted_pin():
    colonised = ":".join(_REAL_FP[i : i + 2] for i in range(0, len(_REAL_FP), 2))
    assert _send(bridge_cert_sha256=colonised)["sent"] is True


def test_pin_mismatch_fails_closed_before_login():
    with pytest.raises(smtp.SmtpError, match="does not match"):
        _send(bridge_cert_sha256="00" * 32)
    conn = _FakeSMTP.instances[0]
    # STARTTLS happened, but credentials were never sent and nothing went out.
    assert "starttls" in conn.events
    assert conn.logged_in is False
    assert conn.sent is False
    assert "login" not in conn.events
