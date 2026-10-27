"""SQLite inventory. Certificates are deduplicated by SHA-256 of the public DER."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path

from certpilot.dates import ensure_utc, format_datetime, parse_datetime
from certpilot.explain import hostname_matches
from certpilot.models import CollectionResult, Gap, Observation, StoredCert, StoredObs
from certpilot.parse import (
    cn_from_subject,
    meta_fingerprint,
    normalize_dn,
    normalize_fingerprint,
    normalize_serial,
    parse_der,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    fingerprint TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    serial TEXT NOT NULL,
    serial_normalized TEXT NOT NULL,
    subject TEXT NOT NULL,
    subject_cn TEXT NOT NULL,
    subject_normalized TEXT NOT NULL,
    issuer TEXT NOT NULL,
    issuer_normalized TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    sans_json TEXT NOT NULL,
    key_type TEXT,
    key_size INTEGER,
    signature_algorithm TEXT,
    self_signed INTEGER NOT NULL,
    is_ca INTEGER,
    subject_key_id TEXT,
    authority_key_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    fingerprint TEXT NOT NULL,
    source TEXT NOT NULL,
    detail TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    requested_name TEXT,
    name_matches INTEGER,
    chain_seen INTEGER NOT NULL,
    chain_fingerprints_json TEXT NOT NULL,
    PRIMARY KEY (fingerprint, source, detail)
);
CREATE TABLE IF NOT EXISTS gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    detail TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_serial
    ON certificates (serial_normalized, issuer_normalized);
"""


class Inventory:
    """A local snapshot. The connection is the caller's to close."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Inventory:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def wipe(self) -> None:
        self.conn.executescript(
            "DELETE FROM observations; DELETE FROM certificates; "
            "DELETE FROM gaps; DELETE FROM warnings;"
        )
        self.conn.commit()

    def replace_sources(self, sources: tuple[str, ...] | list[str]) -> None:
        for source in sources:
            self.conn.execute("DELETE FROM observations WHERE source = ?", (source,))
            self.conn.execute("DELETE FROM gaps WHERE source = ?", (source,))
            self.conn.execute("DELETE FROM warnings WHERE source = ?", (source,))
        self._delete_orphans()
        self.conn.commit()

    def ingest(self, result: CollectionResult, now: dt.datetime | None = None) -> None:
        moment = ensure_utc(now or dt.datetime.now(dt.timezone.utc))
        if result.replaced_sources:
            self.replace_sources(result.replaced_sources)
        for warning in result.warnings:
            self.add_warning(result.replaced_sources[0] if result.replaced_sources else "scan", warning)
        for gap in result.gaps:
            self.add_gap(gap)
        for observation in result.observations:
            self._ingest_observation(observation, moment)
        self.conn.commit()

    def add_warning(self, source: str, message: str) -> None:
        self.conn.execute(
            "INSERT INTO warnings (source, message) VALUES (?, ?)",
            (source, message),
        )

    def add_gap(self, gap: Gap) -> None:
        self.conn.execute(
            "INSERT INTO gaps (source, detail, message) VALUES (?, ?, ?)",
            (gap.source, gap.detail, gap.message),
        )

    def warnings(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT message FROM warnings ORDER BY id"
        ).fetchall()
        return [row["message"] for row in rows]

    def gaps(self) -> list[Gap]:
        rows = self.conn.execute(
            "SELECT source, detail, message FROM gaps ORDER BY id"
        ).fetchall()
        return [Gap(row["source"], row["detail"], row["message"]) for row in rows]

    def certificates(self) -> list[StoredCert]:
        rows = self.conn.execute(
            "SELECT * FROM certificates ORDER BY subject_cn, fingerprint"
        ).fetchall()
        certs: list[StoredCert] = []
        for row in rows:
            obs_rows = self.conn.execute(
                """
                SELECT * FROM observations
                WHERE fingerprint = ?
                ORDER BY source, detail
                """,
                (row["fingerprint"],),
            ).fetchall()
            observations = [
                StoredObs(
                    source=obs["source"],
                    detail=obs["detail"],
                    collected_at=parse_datetime(obs["collected_at"]),
                    requested_name=obs["requested_name"],
                    name_matches=None if obs["name_matches"] is None else bool(obs["name_matches"]),
                    chain_seen=bool(obs["chain_seen"]),
                    chain_fingerprints=json.loads(obs["chain_fingerprints_json"]),
                )
                for obs in obs_rows
            ]
            certs.append(_row_to_cert(row, observations))
        return certs

    def _ingest_observation(self, observation: Observation, now: dt.datetime) -> None:
        if observation.der is None and not observation.meta:
            raise ValueError(f"{observation.source} {observation.detail}: no certificate material")
        chain_fingerprints: list[str] = []
        chain_rows: list[tuple[str, str]] = []
        for index, chain_der in enumerate(observation.chain_ders, start=1):
            parsed = parse_der(chain_der)
            fingerprint = self._upsert_parsed(parsed, now)
            chain_fingerprints.append(fingerprint)
            chain_rows.append((fingerprint, f"chain with {observation.detail} #{index}"))

        if observation.der is not None:
            parsed = parse_der(observation.der)
            fingerprint = self._upsert_parsed(parsed, now)
            name_matches = _name_matches(observation.requested_name, parsed.sans, parsed.subject_cn)
        else:
            fingerprint = self._upsert_meta(observation.meta or {}, now)
            meta = observation.meta or {}
            sans = [str(item) for item in meta.get("sans") or []]
            common_name = str(meta.get("subject_cn") or cn_from_subject(str(meta.get("subject") or "")))
            name_matches = _name_matches(observation.requested_name, sans, common_name)

        chain_fingerprints = [item for item in chain_fingerprints if item != fingerprint]
        self._add_observation(
            fingerprint,
            observation.source,
            observation.detail,
            now,
            observation.requested_name,
            name_matches,
            observation.chain_seen,
            chain_fingerprints,
        )
        chain_source = _chain_source(observation.source)
        for chain_fingerprint, detail in chain_rows:
            others = [item for item in chain_fingerprints if item != chain_fingerprint]
            others.append(fingerprint)
            self._add_observation(
                chain_fingerprint,
                chain_source,
                detail,
                now,
                None,
                None,
                observation.chain_seen,
                others,
            )

    def _upsert_parsed(self, parsed, now: dt.datetime) -> str:
        self._consume_meta_duplicate(parsed.serial_normalized, parsed.issuer_normalized, parsed.fingerprint)
        existing = self.conn.execute(
            "SELECT fingerprint, first_seen FROM certificates WHERE fingerprint = ?",
            (parsed.fingerprint,),
        ).fetchone()
        fields = (
            parsed.fingerprint,
            "der",
            parsed.serial,
            parsed.serial_normalized,
            parsed.subject,
            parsed.subject_cn,
            parsed.subject_normalized,
            parsed.issuer,
            parsed.issuer_normalized,
            format_datetime(parsed.not_before),
            format_datetime(parsed.not_after),
            json.dumps(parsed.sans),
            parsed.key_type,
            parsed.key_size,
            parsed.signature_algorithm,
            int(parsed.self_signed),
            None if parsed.is_ca is None else int(parsed.is_ca),
            parsed.subject_key_id,
            parsed.authority_key_id,
            existing["first_seen"] if existing else format_datetime(now),
            format_datetime(now),
        )
        if existing:
            self.conn.execute(
                """
                UPDATE certificates SET
                    kind=?, serial=?, serial_normalized=?, subject=?, subject_cn=?,
                    subject_normalized=?, issuer=?, issuer_normalized=?, not_before=?,
                    not_after=?, sans_json=?, key_type=?, key_size=?, signature_algorithm=?,
                    self_signed=?, is_ca=?, subject_key_id=?, authority_key_id=?, last_seen=?
                WHERE fingerprint=?
                """,
                fields[1:19] + (fields[20], fields[0]),
            )
        else:
            self.conn.execute(
                """
                INSERT INTO certificates (
                    fingerprint, kind, serial, serial_normalized, subject, subject_cn,
                    subject_normalized, issuer, issuer_normalized, not_before, not_after,
                    sans_json, key_type, key_size, signature_algorithm, self_signed, is_ca,
                    subject_key_id, authority_key_id, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                fields,
            )
        return parsed.fingerprint

    def _upsert_meta(self, meta: dict, now: dt.datetime) -> str:
        subject = str(meta.get("subject") or "")
        common_name = str(meta.get("subject_cn") or meta.get("common_name") or "")
        if not subject and common_name:
            subject = f"CN={common_name}"
        if not common_name:
            common_name = cn_from_subject(subject)
        issuer = str(meta.get("issuer") or "")
        serial = str(meta.get("serial") or "")
        serial_normalized = normalize_serial(serial)
        issuer_normalized = normalize_dn(issuer)
        subject_normalized = normalize_dn(subject)
        fingerprint = normalize_fingerprint(str(meta.get("fingerprint") or meta.get("thumbprint_sha256") or ""))
        kind = "der" if fingerprint else "meta"
        if fingerprint is None:
            if serial_normalized and issuer_normalized:
                found = self.conn.execute(
                    """
                    SELECT fingerprint FROM certificates
                    WHERE kind = 'der' AND serial_normalized = ? AND issuer_normalized = ?
                    """,
                    (serial_normalized, issuer_normalized),
                ).fetchone()
                if found:
                    self.conn.execute(
                        "UPDATE certificates SET last_seen = ? WHERE fingerprint = ?",
                        (format_datetime(now), found["fingerprint"]),
                    )
                    return found["fingerprint"]
            fingerprint = meta_fingerprint(serial, issuer, subject)
            kind = "meta"
        not_before = _required_time(meta, "not_before")
        not_after = _required_time(meta, "not_after")
        sans = [str(item) for item in meta.get("sans") or []]
        key_size = meta.get("key_size")
        is_ca = meta.get("is_ca")
        self_signed = subject_normalized == issuer_normalized and bool(subject_normalized)
        existing = self.conn.execute(
            "SELECT fingerprint, first_seen, kind FROM certificates WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if existing and existing["kind"] == "der":
            self.conn.execute(
                "UPDATE certificates SET last_seen = ? WHERE fingerprint = ?",
                (format_datetime(now), fingerprint),
            )
            return fingerprint
        fields = (
            fingerprint,
            kind,
            serial,
            serial_normalized,
            subject,
            common_name or subject,
            subject_normalized,
            issuer,
            issuer_normalized,
            format_datetime(not_before),
            format_datetime(not_after),
            json.dumps(sans),
            meta.get("key_type"),
            int(key_size) if isinstance(key_size, int) else None,
            meta.get("signature_algorithm"),
            int(self_signed),
            None if is_ca is None else int(bool(is_ca)),
            meta.get("subject_key_id"),
            meta.get("authority_key_id"),
            existing["first_seen"] if existing else format_datetime(now),
            format_datetime(now),
        )
        if existing:
            self.conn.execute("DELETE FROM certificates WHERE fingerprint = ?", (fingerprint,))
        self.conn.execute(
            """
            INSERT INTO certificates (
                fingerprint, kind, serial, serial_normalized, subject, subject_cn,
                subject_normalized, issuer, issuer_normalized, not_before, not_after,
                sans_json, key_type, key_size, signature_algorithm, self_signed, is_ca,
                subject_key_id, authority_key_id, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            fields,
        )
        return fingerprint

    def _consume_meta_duplicate(self, serial_normalized: str, issuer_normalized: str, fingerprint: str) -> None:
        if not serial_normalized or not issuer_normalized:
            return
        rows = self.conn.execute(
            """
            SELECT fingerprint FROM certificates
            WHERE kind = 'meta' AND serial_normalized = ? AND issuer_normalized = ?
            """,
            (serial_normalized, issuer_normalized),
        ).fetchall()
        for row in rows:
            self._repoint(row["fingerprint"], fingerprint)

    def _repoint(self, old_fingerprint: str, new_fingerprint: str) -> None:
        if old_fingerprint == new_fingerprint:
            return
        rows = self.conn.execute(
            "SELECT * FROM observations WHERE fingerprint = ?",
            (old_fingerprint,),
        ).fetchall()
        self.conn.execute("DELETE FROM observations WHERE fingerprint = ?", (old_fingerprint,))
        self.conn.execute("DELETE FROM certificates WHERE fingerprint = ?", (old_fingerprint,))
        for row in rows:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO observations (
                    fingerprint, source, detail, collected_at, requested_name,
                    name_matches, chain_seen, chain_fingerprints_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_fingerprint,
                    row["source"],
                    row["detail"],
                    row["collected_at"],
                    row["requested_name"],
                    row["name_matches"],
                    row["chain_seen"],
                    row["chain_fingerprints_json"],
                ),
            )

    def _add_observation(
        self,
        fingerprint: str,
        source: str,
        detail: str,
        now: dt.datetime,
        requested_name: str | None,
        name_matches: bool | None,
        chain_seen: bool,
        chain_fingerprints: list[str],
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO observations (
                fingerprint, source, detail, collected_at, requested_name,
                name_matches, chain_seen, chain_fingerprints_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                source,
                detail,
                format_datetime(now),
                requested_name,
                None if name_matches is None else int(name_matches),
                int(chain_seen),
                json.dumps(chain_fingerprints),
            ),
        )

    def _delete_orphans(self) -> None:
        self.conn.execute(
            """
            DELETE FROM certificates
            WHERE fingerprint NOT IN (SELECT fingerprint FROM observations)
            """
        )


def _row_to_cert(row: sqlite3.Row, observations: list[StoredObs]) -> StoredCert:
    is_ca = row["is_ca"]
    return StoredCert(
        fingerprint=row["fingerprint"],
        kind=row["kind"],
        serial=row["serial"],
        serial_normalized=row["serial_normalized"],
        subject=row["subject"],
        subject_cn=row["subject_cn"],
        subject_normalized=row["subject_normalized"],
        issuer=row["issuer"],
        issuer_normalized=row["issuer_normalized"],
        not_before=parse_datetime(row["not_before"]),
        not_after=parse_datetime(row["not_after"]),
        sans=json.loads(row["sans_json"]),
        key_type=row["key_type"],
        key_size=row["key_size"],
        signature_algorithm=row["signature_algorithm"],
        self_signed=bool(row["self_signed"]),
        is_ca=None if is_ca is None else bool(is_ca),
        subject_key_id=row["subject_key_id"],
        authority_key_id=row["authority_key_id"],
        observations=observations,
    )


def _required_time(meta: dict, key: str) -> dt.datetime:
    value = meta.get(key)
    if not value:
        raise ValueError(f"certificate metadata is missing {key}")
    if isinstance(value, dt.datetime):
        return ensure_utc(value)
    return parse_datetime(str(value))


def _name_matches(requested: str | None, sans: list[str], common_name: str) -> bool | None:
    if not requested:
        return None
    return hostname_matches(requested, sans, common_name)


def _chain_source(source: str) -> str:
    if source == "tls":
        return "tls-chain"
    return f"{source}-chain"
