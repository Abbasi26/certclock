#!/usr/bin/env python3
"""Read-only certificate metadata collector for Linux hosts.

Uses openssl for parsing and prints one JSON document on stdout.
Private keys are never printed. Run it directly, or from certclock-linux.yml.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".pfx", ".p12"}
_MAX_BYTES = 2_000_000
_CERT_BLOCK = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_PRIVATE = (
    b"-----BEGIN PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN RSA PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN EC PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",  # gitleaks:allow (marker pattern, not key material)
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect public certificate metadata as JSON.")
    parser.add_argument("paths", nargs="+", help="files or directories to read")
    parser.add_argument("--host", default=socket.gethostname())
    args = parser.parse_args(argv)
    warnings: list[str] = []
    certificates: list[dict] = []
    if shutil_which("openssl") is None:
        warnings.append("openssl was not found; no certificates were read")
        _emit(args.host, certificates, warnings)
        return 2
    for path in _files(args.paths, warnings):
        certificates.extend(_read_path(path, warnings))
    _emit(args.host, certificates, warnings)
    return 0


def _emit(host: str, certificates: list[dict], warnings: list[str]) -> None:
    document = {
        "collector": "certclock-linux-files",
        "version": 1,
        "host": host,
        "collected_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "warnings": warnings,
        "certificates": certificates,
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _files(paths: list[str], warnings: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            warnings.append(f"{path}: path does not exist")
            continue
        if path.is_file():
            found.append(path)
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file() and not child.is_symlink() and child.suffix.lower() in _SUFFIXES:
                found.append(child)
    return found


def _read_path(path: Path, warnings: list[str]) -> list[dict]:
    try:
        if path.stat().st_size > _MAX_BYTES:
            warnings.append(f"{path}: larger than {_MAX_BYTES} bytes; skipped")
            return []
        data = path.read_bytes()
    except OSError:
        warnings.append(f"{path}: could not read file; skipped")
        return []
    if path.suffix.lower() in {".pfx", ".p12"}:
        return _read_pfx(path, data, warnings)
    blocks = _CERT_BLOCK.findall(data)
    if any(marker in data for marker in _PRIVATE):
        warnings.append(f"{path}: ignored private key material; only certificates are recorded")
    if blocks:
        rows = []
        for index, block in enumerate(blocks):
            row = _describe_pem(path, block, index if len(blocks) > 1 else None, warnings)
            if row:
                rows.append(row)
        return rows
    row = _describe_file(path, warnings)
    return [row] if row else []


def _read_pfx(path: Path, data: bytes, warnings: list[str]) -> list[dict]:
    completed = _openssl(
        ["openssl", "pkcs12", "-in", str(path), "-nokeys", "-passin", "pass:", "-nomacver"]
    )
    if completed.returncode != 0:
        warnings.append(
            f"{path}: password-protected or unreadable PKCS#12 skipped; "
            "the collector does not ask for passwords"
        )
        return []
    if any(marker in completed.stdout for marker in _PRIVATE):
        warnings.append(f"{path}: PKCS#12 output contained a private key and was discarded")
        return []
    rows = []
    blocks = _CERT_BLOCK.findall(completed.stdout)
    if not blocks:
        warnings.append(f"{path}: PKCS#12 contained no certificates")
        return []
    for index, block in enumerate(blocks):
        row = _describe_pem(path, block, index if len(blocks) > 1 else None, warnings)
        if row:
            rows.append(row)
    return rows


def _describe_pem(path: Path, block: bytes, index: int | None, warnings: list[str]) -> dict | None:
    body = b"".join(
        line.strip() for line in block.splitlines() if line.strip() and not line.startswith(b"-----")
    )
    import base64

    try:
        der = base64.b64decode(body)
    except Exception:
        warnings.append(f"{path}: could not decode a certificate block")
        return None
    with tempfile.TemporaryDirectory(prefix="certclock-") as directory:
        pem_path = Path(directory) / "cert.pem"
        pem_path.write_bytes(block if block.endswith(b"\n") else block + b"\n")
        fields = _openssl_fields(pem_path, "PEM")
    if fields is None:
        warnings.append(f"{path}: openssl could not parse a certificate block")
        return None
    fields["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    fields["path"] = str(path) if index is None else f"{path}#{index}"
    return fields


def _describe_file(path: Path, warnings: list[str]) -> dict | None:
    for inform in ("PEM", "DER"):
        fields = _openssl_fields(path, inform)
        if fields is not None:
            fields["path"] = str(path)
            fields["fingerprint_sha256"] = _der_fingerprint(path, inform)
            return fields
    warnings.append(f"{path}: no certificate found")
    return None


def _der_fingerprint(path: Path, inform: str) -> str:
    completed = _openssl(
        ["openssl", "x509", "-in", str(path), "-inform", inform, "-outform", "DER"]
    )
    if completed.returncode != 0 or not completed.stdout:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(completed.stdout).hexdigest()


def _openssl_fields(path: Path, inform: str) -> dict | None:
    completed = _openssl(
        [
            "openssl", "x509", "-in", str(path), "-inform", inform, "-noout",
            "-nameopt", "RFC2253",
            "-subject", "-issuer", "-startdate", "-enddate", "-serial",
        ]
    )
    if completed.returncode != 0:
        return None
    text = completed.stdout.decode("utf-8", errors="replace")
    values = _pairs(text)
    if "subject" not in values or "notAfter" not in values:
        return None
    details = _openssl(
        ["openssl", "x509", "-in", str(path), "-inform", inform, "-noout", "-text"]
    )
    detail_text = details.stdout.decode("utf-8", errors="replace") if details.returncode == 0 else ""
    san = _openssl(
        ["openssl", "x509", "-in", str(path), "-inform", inform, "-noout", "-ext", "subjectAltName"]
    )
    san_text = san.stdout.decode("utf-8", errors="replace") if san.returncode == 0 else ""
    return {
        "subject": values.get("subject", ""),
        "issuer": values.get("issuer", ""),
        "serial": values.get("serial", "").lower().lstrip("0") or "0",
        "not_before": _openssl_time(values.get("notBefore", "")),
        "not_after": _openssl_time(values.get("notAfter", "")),
        "sans": _sans(san_text),
        "key_type": _key_type(detail_text),
        "key_size": _key_size(detail_text),
        "signature_algorithm": _signature(detail_text),
        "is_ca": _is_ca(detail_text),
    }


def _pairs(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        found[key.strip()] = value.strip()
    return found


def _openssl_time(value: str) -> str:
    if not value:
        return ""
    cleaned = " ".join(value.split())
    try:
        parsed = dt.datetime.strptime(cleaned, "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        return value
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sans(text: str) -> list[str]:
    names = re.findall(r"DNS:([^,\s]+)", text)
    names.extend(re.findall(r"IP Address:([^,\s]+)", text))
    return names


def _key_type(text: str) -> str | None:
    match = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    if not match:
        return None
    algorithm = match.group(1)
    return {
        "rsaEncryption": "RSA",
        "id-ecPublicKey": "EC",
        "dsaEncryption": "DSA",
        "ED25519": "Ed25519",
    }.get(algorithm, algorithm)


def _key_size(text: str) -> int | None:
    match = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
    if not match:
        return None
    return int(match.group(1))


def _signature(text: str) -> str | None:
    match = re.search(r"Signature Algorithm:\s*(\S+)", text)
    return match.group(1) if match else None


def _is_ca(text: str) -> bool | None:
    if "CA:TRUE" in text:
        return True
    if "CA:FALSE" in text:
        return False
    return None


def _openssl(command: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return subprocess.run(
        command,
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )


def shutil_which(name: str) -> str | None:
    from shutil import which

    return which(name)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired:
        print("openssl timed out", file=sys.stderr)
        raise SystemExit(1)
