"""Read public certificates from PEM, DER, and PKCS#12 files.

Password-protected PKCS#12 files are skipped. Private-key PEM blocks are never
stored; a warning is recorded when one was ignored.
"""

from __future__ import annotations

from pathlib import Path

from certpilot.models import CollectionResult, Observation
from certpilot.parse import contains_private_key, load_certificate_bytes, pkcs12_certificates

_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".pfx", ".p12"}
_MAX_BYTES = 2_000_000
_MAX_CERTS = 100


class FileCollector:
    name = "files"
    replaced_sources = ("file",)

    def __init__(self, paths: list[str | Path], max_bytes: int = _MAX_BYTES):
        self.paths = [Path(path) for path in paths]
        self.max_bytes = max_bytes

    def collect(self) -> CollectionResult:
        result = CollectionResult(replaced_sources=self.replaced_sources)
        files: list[Path] = []
        for path in self.paths:
            if not path.exists():
                result.warnings.append(f"{path}: path does not exist; skipped")
                continue
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                for child in _walk(path):
                    files.append(child)
            else:
                result.warnings.append(f"{path}: not a file or directory; skipped")
        for path in files:
            self._read_file(path, result)
        return result

    def _read_file(self, path: Path, result: CollectionResult) -> None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.warnings.append(f"{path}: could not stat file ({exc.errno})")
            return
        if size > self.max_bytes:
            result.warnings.append(
                f"{path}: larger than {self.max_bytes} bytes; skipped so a bundle cannot exhaust memory"
            )
            return
        try:
            data = path.read_bytes()
        except OSError:
            result.warnings.append(f"{path}: could not read file; skipped")
            return
        suffix = path.suffix.lower()
        if suffix in {".pfx", ".p12"}:
            ders, code = pkcs12_certificates(data)
            if code == "password":
                result.warnings.append(
                    f"{path}: password-protected PKCS#12 skipped; CertPilot does not ask for "
                    "passwords and does not store private keys"
                )
                return
            if code == "empty":
                result.warnings.append(f"{path}: PKCS#12 contained no certificates; skipped")
                return
            if code == "unreadable" or not ders:
                result.warnings.append(f"{path}: could not read PKCS#12; skipped")
                return
            self._add(path, ders, result, saw_key=False)
            return
        ders, saw_key = load_certificate_bytes(data)
        if not ders and saw_key:
            result.warnings.append(
                f"{path}: file contains a private key and no certificate; nothing was stored"
            )
            return
        if not ders:
            if suffix in _SUFFIXES or path in self.paths:
                result.warnings.append(f"{path}: no certificates found; skipped")
            return
        self._add(path, ders, result, saw_key=saw_key or contains_private_key(data))

    def _add(self, path: Path, ders: list[bytes], result: CollectionResult, saw_key: bool) -> None:
        if saw_key:
            result.warnings.append(
                f"{path}: ignored private key material; only the certificate was recorded"
            )
        limited = ders[:_MAX_CERTS]
        if len(ders) > _MAX_CERTS:
            result.warnings.append(f"{path}: only the first {_MAX_CERTS} certificates were recorded")
        for index, der in enumerate(limited):
            detail = str(path) if len(limited) == 1 else f"{path}#{index}"
            result.observations.append(
                Observation(source="file", detail=detail, der=der, chain_seen=False)
            )


def _walk(directory: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix.lower() not in _SUFFIXES:
            continue
        found.append(path)
    return found
