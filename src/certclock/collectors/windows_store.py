"""Import JSON written by the bundled Windows certificate-store script.

The script is read-only and exports public metadata. This importer refuses
documents that contain a private-key PEM block.
"""

from __future__ import annotations

import json
from pathlib import Path

from certclock.models import CollectionResult, Observation
from certclock.parse import contains_private_key

_PRIVATE_TEXT = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)


class WindowsStoreCollector:
    name = "windows"
    replaced_sources = ("windows-store",)

    def __init__(self, paths: list[str | Path]):
        self.paths = [Path(path) for path in paths]

    def collect(self) -> CollectionResult:
        result = CollectionResult(replaced_sources=self.replaced_sources)
        for path in self.paths:
            _read_file(path, result)
        return result


def _read_file(path: Path, result: CollectionResult) -> None:
    if not path.is_file():
        result.warnings.append(f"{path}: Windows store export not found; skipped")
        return
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        result.warnings.append(f"{path}: could not read Windows store export; skipped")
        return
    if any(marker in text for marker in _PRIVATE_TEXT) or contains_private_key(text.encode("utf-8", errors="ignore")):
        result.warnings.append(
            f"{path}: export contains private key material and was refused"
        )
        return
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{path}: invalid JSON ({exc.lineno}); skipped")
        return
    host = "unknown-host"
    certificates = document
    if isinstance(document, dict):
        host = str(document.get("host") or host)
        certificates = document.get("certificates", [])
    if isinstance(certificates, dict):
        certificates = [certificates]
    if not isinstance(certificates, list):
        result.warnings.append(f"{path}: expected a certificate list; skipped")
        return
    for index, item in enumerate(certificates, start=1):
        if not isinstance(item, dict):
            result.warnings.append(f"{path}: row {index} is not an object; skipped")
            continue
        meta = _meta(item)
        if meta is None:
            result.warnings.append(f"{path}: row {index} is missing subject or expiry; skipped")
            continue
        location = str(item.get("store_location") or "LocalMachine")
        store = str(item.get("store_name") or "My")
        result.observations.append(
            Observation(
                source="windows-store",
                detail=f"{host} {location}/{store}",
                meta=meta,
            )
        )


def _meta(item: dict) -> dict | None:
    subject = item.get("subject") or ""
    common_name = item.get("common_name") or item.get("subject_cn") or ""
    if not subject and not common_name:
        return None
    if not item.get("not_after"):
        return None
    fingerprint = item.get("thumbprint_sha256") or item.get("fingerprint_sha256") or ""
    return {
        "subject": subject,
        "subject_cn": common_name,
        "issuer": item.get("issuer") or "",
        "serial": item.get("serial") or "",
        "not_before": item.get("not_before") or item.get("not_after"),
        "not_after": item.get("not_after"),
        "sans": item.get("sans") or [],
        "key_type": item.get("key_type"),
        "key_size": item.get("key_size"),
        "signature_algorithm": item.get("signature_algorithm"),
        "fingerprint": fingerprint,
        "is_ca": item.get("is_ca"),
    }
