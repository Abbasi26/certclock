"""Loopback TLS server used by the demo and the tests. It is not a scanner."""

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
from pathlib import Path


class LocalTlsServer:
    """Serve one certificate chain on 127.0.0.1 until ``stop`` is called."""

    def __init__(self, cert_pem: bytes, key_pem: bytes, extra_pem: bytes = b""):
        self._directory = tempfile.TemporaryDirectory(prefix="certpilot-tls-")
        root = Path(self._directory.name)
        cert_path = root / "cert.pem"
        key_path = root / "key.pem"
        cert_path.write_bytes(cert_pem + extra_pem)
        key_path.write_bytes(key_pem)
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(cert_path, key_path)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="certpilot-local-tls", daemon=True)

    def start(self) -> LocalTlsServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        try:
            self._sock.close()
        except OSError:
            pass
        self._directory.cleanup()

    def __enter__(self) -> LocalTlsServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with self._context.wrap_socket(conn, server_side=True):
                    pass
            except Exception:
                try:
                    conn.close()
                except OSError:
                    pass
