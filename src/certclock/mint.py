"""Mint fictional certificates for the demo and the test suite.

SHA-256 certificates are built in process. SHA-1 signatures are delegated to the
OpenSSL CLI because current cryptography releases refuse to create them. Keys
are returned to the caller and are never written by this module.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certclock.parse import pem_certificates

PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey


@dataclass
class Minted:
    certificate: x509.Certificate
    key: PrivateKey | None
    pem: bytes
    der: bytes
    key_pem: bytes | None


def mint(
    common_name: str,
    *,
    sans: list[str] | None = None,
    issuer: Minted | None = None,
    not_before: dt.datetime,
    not_after: dt.datetime,
    key: str = "ec",
    is_ca: bool = False,
    path_length: int | None = None,
) -> Minted:
    """Create a SHA-256 certificate. ``key`` is ``ec``, ``rsa``, or ``rsa1024``."""

    private = _generate_key(key)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_name = subject if issuer is None else issuer.certificate.subject
    issuer_key = private if issuer is None or issuer.key is None else issuer.key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(
                ca=is_ca,
                path_length=0 if is_ca and path_length is None else path_length,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private.public_key()),
            critical=False,
        )
    )
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.certificate.public_key()),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private.public_key()),
            critical=False,
        )
    dns_names = sans if sans is not None else ([] if is_ca else [common_name])
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    certificate = builder.sign(issuer_key, hashes.SHA256())
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    der = certificate.public_bytes(serialization.Encoding.DER)
    key_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return Minted(certificate=certificate, key=private, pem=pem, der=der, key_pem=key_pem)


def mint_sha1(
    issuer: Minted,
    common_name: str,
    *,
    sans: list[str] | None = None,
    days: int = 25,
) -> Minted:
    """Ask OpenSSL to sign a leaf with SHA-1. The leaf key is discarded."""

    if issuer.key is None or issuer.key_pem is None:
        raise RuntimeError("SHA-1 minting needs the issuer private key")
    names = sans if sans is not None else [common_name]
    with tempfile.TemporaryDirectory(prefix="certclock-sha1-") as directory:
        root = Path(directory)
        ca_pem = root / "ca.pem"
        ca_key = root / "ca.key"
        csr = root / "leaf.csr"
        leaf_key = root / "leaf.key"
        ext = root / "ext.cnf"
        out = root / "leaf.pem"
        ca_pem.write_bytes(issuer.pem)
        ca_key.write_bytes(issuer.key_pem)
        ext.write_text(
            "\n".join(
                [
                    "basicConstraints=CA:FALSE",
                    "subjectAltName=" + ",".join(f"DNS:{name}" for name in names),
                    "keyUsage=digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    "authorityKeyIdentifier=keyid,issuer",
                    "",
                ]
            ),
            encoding="ascii",
        )
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(leaf_key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={common_name}",
            ]
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca_pem),
                "-CAkey",
                str(ca_key),
                "-sha1",
                "-days",
                str(days),
                "-CAcreateserial",
                "-out",
                str(out),
                "-extfile",
                str(ext),
            ]
        )
        pem = out.read_bytes()
    certificate = x509.load_pem_x509_certificate(pem)
    ders = pem_certificates(pem)
    der = ders[0] if ders else certificate.public_bytes(serialization.Encoding.DER)
    return Minted(certificate=certificate, key=None, pem=pem, der=der, key_pem=None)


def _generate_key(kind: str) -> PrivateKey:
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "rsa1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    raise ValueError(f"unknown key kind {kind!r}")


def _run(command: list[str]) -> None:
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl is required to mint a SHA-1 certificate") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"openssl failed: {detail}")
