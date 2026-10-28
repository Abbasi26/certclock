"""Import JSON produced by the bundled Linux collector or the Ansible playbook."""

from __future__ import annotations

import json
from pathlib import Path

from certclock.models import CollectionResult, Observation

_PRIVATE_TEXT = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)


class LinuxJsonCollector:
    name = "linux"
    replaced_sources = ("linux-file",)

    def __init__(self, paths: list[str | Path]):
        self.paths = [Path(path) for path in paths]

    def collect(self) -> CollectionResult:
        result = CollectionResult(replaced_sources=self.replaced_sources)
        for path in self.paths:
            _read_file(path, result)
        return result


def _read_file(path: Path, result: CollectionResult) -> None:
    if not path.is_file():
        result.warnings.append(f"{path}: Linux collector JSON not found; skipped")
        return
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        result.warnings.append(f"{path}: could not read Linux collector JSON; skipped")
        return
    if any(marker in text for marker in _PRIVATE_TEXT):
        result.warnings.append(f"{path}: export contains private key material and was refused")
        return
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{path}: invalid JSON ({exc.lineno}); skipped")
        return
    host = path.stem
    certificates = document
    if isinstance(document, dict):
        host = str(document.get("host") or host)
        for warning in document.get("warnings") or []:
            result.warnings.append(f"{host}: {warning}")
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
        if not item.get("not_after") or not (item.get("subject") or item.get("subject_cn")):
            result.warnings.append(f"{path}: row {index} is missing subject or expiry; skipped")
            continue
        remote_path = str(item.get("path") or f"certificate-{index}")
        result.observations.append(
            Observation(
                source="linux-file",
                detail=f"{host}:{remote_path}",
                meta={
                    "subject": item.get("subject") or "",
                    "subject_cn": item.get("subject_cn") or "",
                    "issuer": item.get("issuer") or "",
                    "serial": item.get("serial") or "",
                    "not_before": item.get("not_before") or item.get("not_after"),
                    "not_after": item.get("not_after"),
                    "sans": item.get("sans") or [],
                    "key_type": item.get("key_type"),
                    "key_size": item.get("key_size"),
                    "signature_algorithm": item.get("signature_algorithm"),
                    "fingerprint": item.get("fingerprint_sha256") or "",
                    "is_ca": item.get("is_ca"),
                },
            )
        )
