"""Read public certificates from TLS endpoints. Connections are read-only."""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography import x509

from certclock.hosts import Endpoint
from certclock.models import CollectionResult, Gap, Observation
from certclock.parse import pem_certificates

_CERT_TEXT = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


class TlsCollector:
    name = "tls"
    replaced_sources = ("tls", "tls-chain")

    def __init__(self, endpoints: list[Endpoint], timeout: float = 8.0):
        self.endpoints = endpoints
        self.timeout = timeout

    def collect(self) -> CollectionResult:
        result = CollectionResult(replaced_sources=self.replaced_sources)
        if not self.endpoints:
            return result
        workers = max(1, min(8, len(self.endpoints)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_read_endpoint, endpoint, self.timeout): endpoint
                for endpoint in self.endpoints
            }
            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    outcome = future.result()
                except Exception as exc:
                    result.gaps.append(
                        Gap(
                            "tls",
                            endpoint.detail,
                            f"Could not read a certificate ({type(exc).__name__}).",
                        )
                    )
                    continue
                if isinstance(outcome, Gap):
                    result.gaps.append(outcome)
                else:
                    result.observations.append(outcome)
        result.observations.sort(key=lambda item: item.detail)
        result.gaps.sort(key=lambda item: item.detail)
        return result


def _read_endpoint(endpoint: Endpoint, timeout: float) -> Observation | Gap:
    ders, saw_chain = _chain_from_ssl(endpoint, timeout)
    chain_source = "ssl"
    # openssl can show certificates the ssl module does not expose before 3.13.
    # A leaf from getpeercert() alone is not evidence that the server omitted the chain.
    if not ders or (not saw_chain and shutil.which("openssl")) or (
        saw_chain and len(ders) < 2 and shutil.which("openssl")
    ):
        openssl_ders = _chain_from_openssl(endpoint, timeout)
        if openssl_ders:
            ders = openssl_ders
            saw_chain = True
            chain_source = "openssl"
    if not ders:
        return Gap(
            "tls",
            endpoint.detail,
            "Could not read a certificate. The host did not complete a TLS handshake.",
        )
    leaf, chain = _split_leaf(ders)
    return Observation(
        source="tls",
        detail=f"{endpoint.detail} via {chain_source}",
        der=leaf,
        requested_name=endpoint.sni,
        chain_seen=saw_chain,
        chain_ders=chain,
    )


def _chain_from_ssl(endpoint: Endpoint, timeout: float) -> tuple[list[bytes], bool]:
    """Return certificates and whether the API showed the whole chain, not just the leaf."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=endpoint.sni) as tls:
                if hasattr(tls, "get_unverified_chain"):
                    chain = tls.get_unverified_chain() or []
                    if chain:
                        return list(chain), True
                der = tls.getpeercert(binary_form=True)
                return ([der] if der else []), False
    except (OSError, ssl.SSLError, TimeoutError):
        return [], False


def _chain_from_openssl(endpoint: Endpoint, timeout: float) -> list[bytes]:
    if shutil.which("openssl") is None:
        return []
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    command = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{endpoint.port}",
        "-servername",
        endpoint.sni,
        "-showcerts",
    ]
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    try:
        completed = subprocess.run(
            command,
            input=b"",
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    ders: list[bytes] = []
    for block in _CERT_TEXT.findall(completed.stdout):
        parsed = pem_certificates(block)
        if not parsed:
            continue
        try:
            x509.load_der_x509_certificate(parsed[0])
        except Exception:
            continue
        if parsed[0] not in ders:
            ders.append(parsed[0])
    return ders


def _split_leaf(ders: list[bytes]) -> tuple[bytes, list[bytes]]:
    """Pick the leaf as the certificate that did not issue another one in the chain."""

    parsed = []
    for der in ders:
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception:
            continue
        parsed.append((der, cert))
    if not parsed:
        return ders[0], []
    issuer_names = {
        cert.issuer.rfc4514_string()
        for _der, cert in parsed
        if cert.issuer.rfc4514_string() != cert.subject.rfc4514_string()
    }
    leaves = [der for der, cert in parsed if cert.subject.rfc4514_string() not in issuer_names]
    leaf = leaves[0] if len(leaves) == 1 else parsed[0][0]
    chain = [der for der, _cert in parsed if der != leaf]
    return leaf, chain
