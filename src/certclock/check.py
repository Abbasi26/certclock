"""`certclock check`: a pass/fail gate for CI pipelines, cron, and pre-change checks.

Exit codes:

* 0 - nothing at or past the failing level
* 1 - at least one certificate is at WARN (only with ``--fail-on warn``)
* 2 - at least one certificate is at CRIT or already expired
* 3 - usage or input error (bad host list, unreadable path, ...)

``check`` can read an existing inventory (``--db``) or collect ad hoc from
``--host`` and ``--path`` into a throwaway database, so a single command works
in a CI job without a config file.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from certclock import __version__
from certclock.collectors.files import FileCollector
from certclock.collectors.tls import TlsCollector
from certclock.config import Config
from certclock.dates import format_date, format_datetime, utcnow
from certclock.hosts import parse_hosts
from certclock.inventory import Inventory
from certclock.models import Gap, Report
from certclock.outputs.markdown import render_markdown, status_code, status_label
from certclock.pipeline import build_report


def _deduplicate_certs(certs: list) -> list:
    """Deduplicate StoredCert entries by SHA-256 fingerprint, merging observations.

    When the same certificate (same fingerprint) appears in both the production
    database and the temporary ad-hoc database, combine their observations
    instead of creating duplicate report rows.
    """
    from certclock.models import StoredCert

    by_fp: dict[str, StoredCert] = {}
    for cert in certs:
        if cert.fingerprint not in by_fp:
            by_fp[cert.fingerprint] = cert
        else:
            # Merge observations: combine both lists, avoiding exact duplicates
            existing = by_fp[cert.fingerprint]
            existing_details = {(obs.source, obs.detail) for obs in existing.observations}
            merged_obs = list(existing.observations)
            for obs in cert.observations:
                if (obs.source, obs.detail) not in existing_details:
                    merged_obs.append(obs)
                    existing_details.add((obs.source, obs.detail))
            # Create new StoredCert with merged observations (StoredCert is not frozen)
            by_fp[cert.fingerprint] = StoredCert(
                fingerprint=existing.fingerprint,
                kind=existing.kind,
                serial=existing.serial,
                serial_normalized=existing.serial_normalized,
                subject=existing.subject,
                subject_cn=existing.subject_cn,
                subject_normalized=existing.subject_normalized,
                issuer=existing.issuer,
                issuer_normalized=existing.issuer_normalized,
                not_before=existing.not_before,
                not_after=existing.not_after,
                sans=existing.sans,
                key_type=existing.key_type,
                key_size=existing.key_size,
                signature_algorithm=existing.signature_algorithm,
                self_signed=existing.self_signed,
                is_ca=existing.is_ca,
                subject_key_id=existing.subject_key_id,
                authority_key_id=existing.authority_key_id,
                observations=merged_obs,
            )
    return list(by_fp.values())

EXIT_OK = 0
EXIT_WARN = 1
EXIT_CRIT = 2
EXIT_ERROR = 3


@dataclass
class CheckOutcome:
    report: Report
    worst: int
    exit_code: int


def evaluate(report: Report, fail_on: str = "crit") -> CheckOutcome:
    if fail_on not in {"warn", "crit", "never"}:
        raise ValueError(f"fail_on must be warn, crit, or never, not {fail_on!r}")
    worst = 0
    for cert in report.certificates:
        worst = max(worst, status_code(cert, report.warn_days, report.crit_days))
    if fail_on == "never":
        code = EXIT_OK
    elif worst == 2:
        code = EXIT_CRIT
    elif worst == 1 and fail_on == "warn":
        code = EXIT_WARN
    else:
        code = EXIT_OK
    return CheckOutcome(report=report, worst=worst, exit_code=code)


def run_check(
    *,
    db: str | None,
    hosts: list[str],
    paths: list[str],
    owners: str | None = None,
    warn_days: int = 30,
    crit_days: int = 7,
    max_validity_days: int = 100,
    timeout: float = 8.0,
    fail_on: str = "crit",
) -> CheckOutcome:
    if not db and not hosts and not paths:
        raise ValueError("pass --db, or at least one --host or --path")
    if crit_days > warn_days:
        raise ValueError("--crit-days must not be larger than --warn-days")

    config = Config(
        database="",
        owners_file=owners,
        horizon_days=max(90, warn_days),
        warn_days=warn_days,
        crit_days=crit_days,
        notify_within_days=warn_days,
        weak_rsa_bits=2048,
        max_validity_days=max_validity_days,
    )
    config._base_dir = Path.cwd()  # noqa: SLF001
    now = utcnow()

    # Case A: db provided, no ad-hoc collection -> read prod DB only
    if db and not hosts and not paths:
        with Inventory(db) as inventory:
            report = build_report(inventory, config, now)
        return evaluate(report, fail_on)

    # Case B: db provided AND ad-hoc collection -> merge prod + temp
    if db and (hosts or paths):
        with Inventory(db) as prod_inventory:
            prod_certs = prod_inventory.certificates()
            prod_gaps = prod_inventory.gaps()
            prod_warnings = prod_inventory.warnings()

        with tempfile.TemporaryDirectory(prefix="certclock-check-") as scratch:
            temp_db = str(Path(scratch) / "check.db")
            with Inventory(temp_db) as temp_inventory:
                if hosts:
                    endpoints = parse_hosts("\n".join(hosts))
                    temp_inventory.ingest(TlsCollector(endpoints, timeout=timeout).collect(), now)
                if paths:
                    temp_inventory.ingest(FileCollector(paths).collect(), now)
                temp_certs = temp_inventory.certificates()
                temp_gaps = temp_inventory.gaps()
                temp_warnings = temp_inventory.warnings()

        # Merge certificates, gaps, warnings
        all_certs = _deduplicate_certs(prod_certs + temp_certs)
        all_gaps = prod_gaps + temp_gaps
        all_warnings = prod_warnings + temp_warnings

        # Build merged report directly
        report = _build_merged_report(
            all_certs, all_gaps, all_warnings, config, now
        )
        return evaluate(report, fail_on)

    # Case C: no db -> current behaviour (temp DB only)
    with tempfile.TemporaryDirectory(prefix="certclock-check-") as scratch:
        database = str(Path(scratch) / "check.db")
        with Inventory(database) as inventory:
            if hosts:
                endpoints = parse_hosts("\n".join(hosts))
                inventory.ingest(TlsCollector(endpoints, timeout=timeout).collect(), now)
            if paths:
                inventory.ingest(FileCollector(paths).collect(), now)
            report = build_report(inventory, config, now)
    return evaluate(report, fail_on)


def _build_merged_report(
    certs: list,
    gaps: list[Gap],
    warnings: list[str],
    config: Config,
    now,
) -> Report:
    """Build a Report from pre-collected StoredCert objects."""
    from certclock.explain import explain
    from certclock.owners import assign_owners, load_owners

    rules = []
    owners_file = config.resolve(config.owners_file)
    if owners_file:
        rules = load_owners(owners_file)

    # Deduplicate by fingerprint and merge observations
    certs = _deduplicate_certs(certs)

    rows = explain(
        certs,
        now,
        weak_rsa_bits=config.weak_rsa_bits,
        max_validity_days=config.max_validity_days,
        owners=assign_owners(certs, rules),
    )
    return Report(
        generated_at=now,
        certificates=rows,
        gaps=gaps,
        warnings=warnings,
        horizon_days=config.horizon_days,
        warn_days=config.warn_days,
        crit_days=config.crit_days,
        notify_within_days=config.notify_within_days,
    )


def render_text(outcome: CheckOutcome) -> str:
    report = outcome.report
    counts = report.summary()
    label = {0: "OK", 1: "WARN", 2: "CRIT"}[outcome.worst]
    lines = [
        f"{label}: {counts['total']} certificates, {counts['expired']} expired, "
        f"{counts['within_7']} within 7 days, {counts['within_30']} within 30 days"
    ]
    flagged = [
        cert
        for cert in sorted(report.certificates, key=lambda c: c.days_remaining)
        if status_code(cert, report.warn_days, report.crit_days) > 0
    ]
    for cert in flagged:
        lines.append(
            f"  {status_label(cert, report.warn_days, report.crit_days):4} "
            f"{cert.days_remaining:>5}d  {cert.subject_cn or cert.fingerprint[:16]}"
            f"  ({', '.join(obs.detail for obs in cert.sources)[:120]})"
        )
    for cert in _long_validity(report):
        lines.append(
            f"  LONG {cert.subject_cn or cert.fingerprint[:16]}: valid "
            f"{format_date(cert.not_before)} to {format_date(cert.not_after)}"
        )
    for gap in report.gaps:
        lines.append(f"  GAP  {gap.source} {gap.detail}: {gap.message}")
    return "\n".join(lines) + "\n"


def render_json_outcome(outcome: CheckOutcome) -> str:
    report = outcome.report
    document = {
        "tool": "certclock",
        "version": __version__,
        "generated_at": format_datetime(report.generated_at),
        "status": {0: "ok", 1: "warn", 2: "crit"}[outcome.worst],
        "exit_code": outcome.exit_code,
        "warn_days": report.warn_days,
        "crit_days": report.crit_days,
        "summary": report.summary(),
        "flagged": [
            {
                "common_name": cert.subject_cn,
                "fingerprint": cert.fingerprint,
                "days_remaining": cert.days_remaining,
                "not_after": format_datetime(cert.not_after),
                "status": status_label(cert, report.warn_days, report.crit_days).lower(),
                "sources": [obs.detail for obs in cert.sources],
            }
            for cert in sorted(report.certificates, key=lambda c: c.days_remaining)
            if status_code(cert, report.warn_days, report.crit_days) > 0
        ],
        "long_validity": [
            {
                "common_name": cert.subject_cn,
                "fingerprint": cert.fingerprint,
                "not_before": format_datetime(cert.not_before),
                "not_after": format_datetime(cert.not_after),
                "message": next(p.message for p in cert.problems if p.code == "long_validity"),
            }
            for cert in _long_validity(report)
        ],
        "gaps": [{"source": g.source, "detail": g.detail, "message": g.message} for g in report.gaps],
    }
    return json.dumps(document, indent=2) + "\n"


def _long_validity(report) -> list:
    return [
        cert
        for cert in report.certificates
        if any(problem.code == "long_validity" for problem in cert.problems)
    ]


def render(outcome: CheckOutcome, fmt: str) -> str:
    if fmt == "json":
        return render_json_outcome(outcome)
    if fmt == "markdown":
        return render_markdown(outcome.report)
    return render_text(outcome)
