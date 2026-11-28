"""Shared fixtures. Certificates are generated in process; tests do not use the network."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from pathlib import Path

import pytest

from certclock.dates import utcnow
from certclock.mint import Minted, mint


class LocalSmtpServer:
    def __init__(self, cert_path: Path, key_path: Path, mode: str = "starttls"):
        self.mode = mode
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(cert_path, key_path)
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                if self.mode == "timeout":
                    self._stop.wait(1)
                    continue
                if self.mode == "invalid":
                    conn.sendall(b"not smtp\r\n")
                    continue
                conn.sendall(b"220 smtp.example.test ready\r\n")
                if not conn.recv(8192).upper().startswith(b"EHLO "):
                    continue
                if self.mode == "ehlo-error":
                    conn.sendall(b"500 EHLO rejected\r\n")
                    continue
                if self.mode == "no-starttls":
                    conn.sendall(b"250 smtp.example.test\r\n")
                    continue
                conn.sendall(b"250-smtp.example.test\r\n250 STARTTLS\r\n")
                if conn.recv(8192).upper().strip() != b"STARTTLS":
                    continue
                if self.mode == "starttls-error":
                    conn.sendall(b"454 TLS unavailable\r\n")
                    continue
                conn.sendall(b"220 Begin TLS\r\n")
                try:
                    with self._context.wrap_socket(conn, server_side=True):
                        pass
                except (OSError, ssl.SSLError):
                    pass


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def leaf(now: dt.datetime) -> Minted:
    issuer = mint(
        "Example Laboratory Issuing CA",
        is_ca=True,
        key="ec",
        path_length=0,
        sans=[],
        not_before=now - dt.timedelta(days=10),
        not_after=now + dt.timedelta(days=80),
    )
    return mint(
        "app.example.test",
        issuer=issuer,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=40),
    )


def write_pem(directory: Path, name: str, minted: Minted) -> Path:
    path = directory / name
    path.write_bytes(minted.pem)
    return path


@pytest.fixture
def clock() -> dt.datetime:
    return utcnow()


@pytest.fixture
def smtp_server(tmp_path: Path):
    def create(minted: Minted, mode: str = "starttls") -> LocalSmtpServer:
        cert_path = tmp_path / f"smtp-{mode}.pem"
        key_path = tmp_path / f"smtp-{mode}.key"
        cert_path.write_bytes(minted.pem)
        key_path.write_bytes(minted.key_pem)
        return LocalSmtpServer(cert_path, key_path, mode)

    return create
