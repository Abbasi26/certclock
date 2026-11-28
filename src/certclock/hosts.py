"""Parse a TLS host list. Lines are ``host:port`` or ``host:port sni``.

Also accepts HTTP(S) URLs and SMTP STARTTLS URLs such as ``smtp://host:25``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    sni: str
    line: str
    transport: str = "tls"

    @property
    def detail(self) -> str:
        if self.transport == "smtp":
            host = f"[{self.host}]" if ":" in self.host else self.host
            return f"smtp://{host}:{self.port} SNI {self.sni}"
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
    parts = raw.split()
    if len(parts) > 2:
        raise ValueError("expected endpoint and optional SNI")
    sni: str | None = None
    endpoint = parts[0]
    if len(parts) > 1:
        sni = parts[1]

    transport = "tls"
    # Accept full URLs like https://host:port/path and strip scheme/path.
    if endpoint.startswith("smtp://"):
        parsed = urlparse(endpoint)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("SMTP endpoints must not contain userinfo")
        try:
            port = parsed.port if parsed.port is not None else 25
        except ValueError as exc:
            raise ValueError(f"bad port in {endpoint!r}") from exc
        host = parsed.hostname or ""
        transport = "smtp"
        endpoint = ""
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        endpoint = _strip_url_scheme_and_path(endpoint)

    if not endpoint:
        pass
    elif endpoint.startswith("["):
        end = endpoint.find("]")
        if end < 0:
            raise ValueError("unclosed IPv6 bracket")
        host = endpoint[1:end]
        rest = endpoint[end + 1 :].strip()
        if not rest.startswith(":"):
            raise ValueError("IPv6 endpoints need [address]:port")
        port_text = rest[1:]
        if not port_text.isdigit():
            raise ValueError("missing port")
        port = int(port_text)
    else:
        if ":" in endpoint:
            host, port_text = endpoint.rsplit(":", 1)
            if not port_text.isdigit():
                raise ValueError(f"bad port in {endpoint!r}")
            port = int(port_text)
        else:
            host = endpoint
            port = 443
    if not host:
        raise ValueError("missing host")
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range")
    return Endpoint(host=host, port=port, sni=sni or host, line=original, transport=transport)


def _strip_url_scheme_and_path(url: str) -> str:
    """Strip scheme and path from a URL, returning host:port."""
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"invalid URL: {url!r}")
    hostport = parsed.netloc
    # Remove userinfo if present (e.g., user:pass@host:port)
    if "@" in hostport:
        hostport = hostport.split("@", 1)[1]
    return hostport
