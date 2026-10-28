"""Parse a TLS host list. Lines are ``host:port`` or ``host:port sni``."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    sni: str
    line: str

    @property
    def detail(self) -> str:
        return f"{self.host}:{self.port} SNI {self.sni}"


def parse_hosts(text: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        try:
            endpoints.append(_parse_line(raw, line.strip()))
        except ValueError as exc:
            raise ValueError(f"hosts line {lineno}: {exc}") from exc
    return endpoints


def load_hosts(path: str | Path) -> list[Endpoint]:
    return parse_hosts(Path(path).read_text(encoding="utf-8"))


def _parse_line(raw: str, original: str) -> Endpoint:
    if len(raw.split()) > 2:
        raise ValueError("expected endpoint and optional SNI")
    sni: str | None = None
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0:
            raise ValueError("unclosed IPv6 bracket")
        host = raw[1:end]
        rest = raw[end + 1 :].strip()
        if not rest.startswith(":"):
            raise ValueError("IPv6 endpoints need [address]:port")
        parts = rest[1:].split()
        if not parts or not parts[0].isdigit():
            raise ValueError("missing port")
        port = int(parts[0])
        if len(parts) > 1:
            sni = parts[1]
    else:
        parts = raw.split()
        hostport = parts[0]
        if len(parts) > 1:
            sni = parts[1]
        if ":" in hostport:
            host, port_text = hostport.rsplit(":", 1)
            if not port_text.isdigit():
                raise ValueError(f"bad port in {hostport!r}")
            port = int(port_text)
        else:
            host = hostport
            port = 443
    if not host:
        raise ValueError("missing host")
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range")
    return Endpoint(host=host, port=port, sni=sni or host, line=original)
