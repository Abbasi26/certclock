"""Parse public certificates. Private keys are detected only so they can be dropped."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from certclock.dates import ensure_utc

_CERT_BLOCK = re.compile(
    b"-----BEGIN (?:TRUSTED )?CERTIFICATE-----"
    b".*?"
    b"-----END (?:TRUSTED )?CERTIFICATE-----",
    re.DOTALL,
)
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN RSA PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN EC PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN OPENSSH PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
)
_SHA1_OIDS = {
    "1.2.840.113549.1.1.5",
    "1.2.840.10040.4.3",
    "1.2.840.10045.4.1",
}
_HEADER_ALIASES = {
    "requestid": "request_id",
    "requestername": "requester",
    "requestcommonname": "common_name",
    "commonname": "common_name",
    "certificatesubject": "subject",
    "distinguishedname": "subject",
    "subject": "subject",
    "certificateexpirationdate": "not_after",
    "notafter": "not_after",
    "expirationdate": "not_after",
    "certificateeffectivedate": "not_before",
    "notbefore": "not_before",
    "effectivedate": "not_before",
    "serialnumber": "serial",
    "serial": "serial",
    "certificatehash": "thumbprint",
    "certificatehashsha256": "thumbprint_sha256",
    "sha256hash": "thumbprint_sha256",
    "thumbprintsha256": "thumbprint_sha256",
    "thumbprint": "thumbprint",
    "certificateissuername": "issuer",
    "issuername": "issuer",
    "issuer": "issuer",
    "certificatetemplate": "template",
    "requestdisposition": "disposition",
    "disposition": "disposition",
}


@dataclass
class ParsedCert:
    der: bytes
    fingerprint: str
    serial: str
    serial_normalized: str
    subject: str
    subject_cn: str
    subject_normalized: str
    issuer: str
    issuer_normalized: str
    not_before: object
    not_after: object
    sans: list[str]
    key_type: str | None
    key_size: int | None
    signature_algorithm: str | None
    self_signed: bool
    is_ca: bool | None
    subject_key_id: str | None
    authority_key_id: str | None


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def normalize_serial(serial: str) -> str:
    cleaned = serial.strip().lower().replace(" ", "").replace(":", "")
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        return ""
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        return cleaned
    return cleaned.lstrip("0") or "0"


def normalize_dn(dn: str) -> str:
    parts: list[str] = []
    for part in dn.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
            parts.append(f"{key.strip().lower()}={value.strip().lower()}")
        else:
            parts.append(part.lower())
    return ",".join(parts)


def meta_fingerprint(serial: str, issuer: str, subject: str) -> str:
    material = f"{normalize_serial(serial)}|{normalize_dn(issuer)}|{normalize_dn(subject)}"
    return "meta:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalize_fingerprint(value: str) -> str | None:
    """Return a SHA-256 hex fingerprint, or None if the value is not one."""

    cleaned = value.strip().lower().replace(" ", "").replace(":", "")
    if re.fullmatch(r"[0-9a-f]{64}", cleaned):
        return cleaned
    return None


def cn_from_subject(subject: str) -> str:
    for part in subject.split(","):
        part = part.strip()
        if part.lower().startswith("cn="):
            return part.split("=", 1)[1].strip() or subject
    return subject


def contains_private_key(data: bytes) -> bool:
    return any(marker in data for marker in _PRIVATE_MARKERS)


def pem_certificates(data: bytes) -> list[bytes]:
    """Return the DER encoding of each certificate block. Key blocks are ignored."""

    ders: list[bytes] = []
    for block in _CERT_BLOCK.findall(data):
        body = b"".join(
            line.strip()
            for line in block.splitlines()
            if line.strip() and not line.startswith(b"-----")
        )
        try:
            ders.append(base64.b64decode(body, validate=False))
        except Exception:
            continue
    return ders


def pkcs12_certificates(data: bytes) -> tuple[list[bytes], str | None]:
    """Extract public certificates from a PKCS#12 blob.

    Returns ``(ders, warning_code)``. The private key is discarded immediately.
    ``warning_code`` is ``password`` when the blob is encrypted, ``empty`` when
    it has no certificates, ``unreadable`` when it is not PKCS#12, or None.
    """

    last_error: Exception | None = None
    for password in (None, b""):
        try:
            key, cert, extras = pkcs12.load_key_and_certificates(data, password)
        except ValueError as exc:
            last_error = exc
            continue
        except Exception as exc:
            last_error = exc
            continue
        del key
        ders: list[bytes] = []
        if cert is not None:
            ders.append(cert.public_bytes(Encoding.DER))
        for extra in extras or []:
            ders.append(extra.public_bytes(Encoding.DER))
        if not ders:
            return [], "empty"
        return ders, None
    if last_error is None:
        return [], "unreadable"
    text = str(last_error).lower()
    if "password" in text or "invalid" in text or "decrypt" in text:
        return [], "password"
    return [], "password" if data[:1] == b"0" or data[:4] == b"\x30" else "unreadable"


def load_certificate_bytes(data: bytes) -> tuple[list[bytes], bool]:
    """Load every public certificate in ``data``.

    The boolean is true when a private-key PEM block was present and ignored.
    """

    saw_key = contains_private_key(data)
    if b"-----BEGIN" in data:
        return pem_certificates(data), saw_key
    try:
        cert = x509.load_der_x509_certificate(data)
    except Exception:
        return [], saw_key
    return [cert.public_bytes(Encoding.DER)], saw_key


def is_sha1(signature_algorithm: str | None) -> bool:
    if not signature_algorithm:
        return False
    compact = signature_algorithm.strip().lower().replace("-", "").replace("_", "")
    if compact in _SHA1_OIDS:
        return True
    if any(token in compact for token in ("sha256", "sha384", "sha512", "sha224")):
        return False
    return "sha1" in compact


def _cn(name: x509.Name) -> str:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        text = name.rfc4514_string()
        return text or "(no subject)"
    value = attributes[0].value
    return value if isinstance(value, str) else str(value)


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    for item in ext.value:
        if isinstance(item, x509.DNSName):
            names.append(item.value)
        elif isinstance(item, x509.IPAddress):
            names.append(str(item.value))
        elif isinstance(item, (x509.UniformResourceIdentifier, x509.RFC822Name)):
            names.append(str(item.value))
        else:
            names.append(str(getattr(item, "value", item)))
    return names


def _key_info(cert: x509.Certificate) -> tuple[str | None, int | None]:
    public = cert.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        return "RSA", public.key_size
    if isinstance(public, ec.EllipticCurvePublicKey):
        return "EC", public.key_size
    if isinstance(public, dsa.DSAPublicKey):
        return "DSA", public.key_size
    if isinstance(public, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(public, ed448.Ed448PublicKey):
        return "Ed448", None
    return type(public).__name__, None


def _signature_name(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    name = getattr(oid, "_name", "") or ""
    if name and not name[0].isdigit():
        return name
    digest = cert.signature_hash_algorithm
    if digest is not None:
        return digest.name
    return oid.dotted_string


def _is_ca(cert: x509.Certificate) -> bool | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return None
    return bool(ext.value.ca)


def _key_id(cert: x509.Certificate, kind: str) -> str | None:
    try:
        if kind == "ski":
            ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            return ext.value.key_identifier.hex()
        ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        if ext.value.key_identifier:
            return ext.value.key_identifier.hex()
    except x509.ExtensionNotFound:
        return None
    return None


def parse_der(der: bytes) -> ParsedCert:
    cert = x509.load_der_x509_certificate(der)
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    key_type, key_size = _key_info(cert)
    serial_hex = format(cert.serial_number, "x")
    return ParsedCert(
        der=der,
        fingerprint=fingerprint_der(der),
        serial=serial_hex,
        serial_normalized=normalize_serial(serial_hex),
        subject=subject,
        subject_cn=_cn(cert.subject) or subject,
        subject_normalized=normalize_dn(subject),
        issuer=issuer,
        issuer_normalized=normalize_dn(issuer),
        not_before=ensure_utc(cert.not_valid_before_utc),
        not_after=ensure_utc(cert.not_valid_after_utc),
        sans=_sans(cert),
        key_type=key_type,
        key_size=key_size,
        signature_algorithm=_signature_name(cert),
        self_signed=subject == issuer,
        is_ca=_is_ca(cert),
        subject_key_id=_key_id(cert, "ski"),
        authority_key_id=_key_id(cert, "aki"),
    )


def header_key(header: str) -> str | None:
    return _HEADER_ALIASES.get(re.sub(r"[^a-z0-9]", "", header.lower()))
