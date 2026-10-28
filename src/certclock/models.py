"""Data records shared by collectors, the inventory, and reports.

Collectors return public certificate material only. Nothing in these records
is a private key.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Problem:
    """One plain-language finding about a certificate."""

    code: str
    message: str


@dataclass
class Observation:
    """A single sighting of a certificate from one source.

    Provide ``der`` when the public certificate bytes are available. Otherwise
    provide ``meta``. Chain certificates that arrived with this sighting go in
    ``chain_ders`` and are inventoried as their own rows.
    """

    source: str
    detail: str
    der: bytes | None = None
    meta: dict | None = None
    requested_name: str | None = None
    chain_seen: bool = False
    chain_ders: list[bytes] = field(default_factory=list)


@dataclass
class Gap:
    """A source location that was requested but yielded no certificate."""

    source: str
    detail: str
    message: str


@dataclass
class CollectionResult:
    """What one collector read. ``replaced_sources`` are wiped before ingest."""

    observations: list[Observation] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    replaced_sources: tuple[str, ...] = ()


@dataclass
class StoredObs:
    source: str
    detail: str
    collected_at: dt.datetime
    requested_name: str | None
    name_matches: bool | None
    chain_seen: bool
    chain_fingerprints: list[str]


@dataclass
class StoredCert:
    fingerprint: str
    kind: str
    serial: str
    serial_normalized: str
    subject: str
    subject_cn: str
    subject_normalized: str
    issuer: str
    issuer_normalized: str
    not_before: dt.datetime
    not_after: dt.datetime
    sans: list[str]
    key_type: str | None
    key_size: int | None
    signature_algorithm: str | None
    self_signed: bool
    is_ca: bool | None
    subject_key_id: str | None
    authority_key_id: str | None
    observations: list[StoredObs]


@dataclass
class ReportCert:
    fingerprint: str
    serial: str
    subject: str
    subject_cn: str
    issuer: str
    not_before: dt.datetime
    not_after: dt.datetime
    days_remaining: int
    bucket: str
    sans: list[str]
    key_type: str | None
    key_size: int | None
    signature_algorithm: str | None
    self_signed: bool
    is_ca: bool | None
    owner: str | None
    service: str | None
    owner_note: str | None
    dependency_note: str | None
    problems: list[Problem]
    sources: list[StoredObs]

    @property
    def search_text(self) -> str:
        parts = [
            self.subject_cn,
            self.subject,
            self.issuer,
            self.owner or "",
            self.service or "",
            self.dependency_note or "",
            self.signature_algorithm or "",
            " ".join(self.sans),
            " ".join(problem.message for problem in self.problems),
            " ".join(f"{obs.source} {obs.detail}" for obs in self.sources),
        ]
        return " ".join(parts)


@dataclass
class Report:
    generated_at: dt.datetime
    certificates: list[ReportCert]
    gaps: list[Gap]
    warnings: list[str]
    horizon_days: int
    warn_days: int
    crit_days: int
    notify_within_days: int

    def summary(self) -> dict[str, int]:
        counts = {
            "total": len(self.certificates),
            "expired": 0,
            "within_7": 0,
            "within_30": 0,
            "within_90": 0,
            "later": 0,
        }
        for cert in self.certificates:
            counts[cert.bucket] += 1
        return counts
