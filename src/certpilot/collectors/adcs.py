"""Import a ``certutil -view`` CSV export of issued certificates.

CertPilot does not run certutil itself in v0.1. Produce the CSV on the CA,
then import it. Rows that are not issued are skipped when a disposition column
is present. A default issuer can be supplied because many certutil column sets
omit the issuer distinguished name, and dependency notes need it.
"""

from __future__ import annotations

import csv
from pathlib import Path

from certpilot.models import CollectionResult, Observation
from certpilot.parse import header_key

_ISSUED = {"20", "issued", "issuedcertificate"}


class AdcsCollector:
    name = "adcs"
    replaced_sources = ("adcs",)

    def __init__(self, sources: list[dict]):
        """``sources`` items have ``path`` and an optional ``issuer``."""

        self.sources = sources

    def collect(self) -> CollectionResult:
        result = CollectionResult(replaced_sources=self.replaced_sources)
        for source in self.sources:
            _read_csv(Path(source["path"]), source.get("issuer") or "", result)
        return result


def _read_csv(path: Path, default_issuer: str, result: CollectionResult) -> None:
    if not path.is_file():
        result.warnings.append(f"{path}: ADCS CSV not found; skipped")
        return
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        result.warnings.append(f"{path}: could not read ADCS CSV; skipped")
        return
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("CertUtil:")]
    header_index = None
    for index, line in enumerate(lines):
        if _looks_like_header(line):
            header_index = index
            break
    if header_index is None:
        result.warnings.append(f"{path}: no certutil header row found; skipped")
        return
    reader = csv.reader(lines[header_index:])
    try:
        header = next(reader)
    except StopIteration:
        result.warnings.append(f"{path}: empty ADCS CSV; skipped")
        return
    keys = [header_key(column) for column in header]
    if not any(key in {"not_after", "common_name", "subject", "serial"} for key in keys):
        result.warnings.append(f"{path}: header is not a certificate view; skipped")
        return
    skipped = 0
    kept = 0
    for row_number, row in enumerate(reader, start=header_index + 2):
        if not any(cell.strip() for cell in row):
            continue
        if row[0].startswith("CertUtil:"):
            continue
        record = {}
        for key, cell in zip(keys, row):
            if key:
                record[key] = cell.strip().strip('"')
        disposition = record.get("disposition", "")
        if disposition:
            token = "".join(disposition.lower().split())
            if token not in _ISSUED and not token.startswith("20"):
                skipped += 1
                continue
        meta = _meta(record, default_issuer)
        if meta is None:
            result.warnings.append(f"{path}: row {row_number} is missing a name or expiry; skipped")
            continue
        request_id = record.get("request_id") or str(kept + 1)
        template = record.get("template") or "unspecified"
        requester = record.get("requester") or "unknown"
        result.observations.append(
            Observation(
                source="adcs",
                detail=f"request {request_id} template {template} requester {requester}",
                meta=meta,
            )
        )
        kept += 1
    if skipped:
        result.warnings.append(f"{path}: skipped {skipped} rows that were not issued certificates")
    if kept == 0 and skipped == 0:
        result.warnings.append(f"{path}: no certificate rows found")


def _looks_like_header(line: str) -> bool:
    lowered = line.lower()
    tokens = ("common name", "commonname", "notafter", "not after", "expiration", "serial")
    return any(token in lowered for token in tokens)


def _meta(record: dict, default_issuer: str) -> dict | None:
    common_name = record.get("common_name") or ""
    subject = record.get("subject") or (f"CN={common_name}" if common_name else "")
    not_after = record.get("not_after")
    if not subject or not not_after:
        return None
    issuer = record.get("issuer") or default_issuer
    not_before = record.get("not_before") or not_after
    return {
        "subject": subject,
        "subject_cn": common_name,
        "issuer": issuer,
        "serial": record.get("serial") or "",
        "not_before": not_before,
        "not_after": not_after,
        "sans": [common_name] if common_name else [],
        "fingerprint": record.get("thumbprint_sha256") or "",
        "signature_algorithm": None,
        "key_type": None,
        "key_size": None,
    }
