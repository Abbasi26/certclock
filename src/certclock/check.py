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
from certclock.dates import format_datetime, utcnow
from certclock.hosts import load_hosts, parse_hosts
from certclock.inventory import Inventory
from certclock.models import Report
from certclock.outputs.markdown import render_markdown, status_code, status_label
from certclock.pipeline import build_report

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
    timeout: float = 8.0,
    fail_on: str = "crit",
    hosts_file: str | None = None,
) -> CheckOutcome:
    if not db and not hosts and not paths and not hosts_file:
        raise ValueError("pass --db, or at least one --host, --host-file, or --path")
    if crit_days > warn_days:
        raise ValueError("--crit-days must not be larger than --warn-days")
    config = Config(
        database=db or "",
        owners_file=owners,
        horizon_days=max(90, warn_days),
        warn_days=warn_days,
        crit_days=crit_days,
        notify_within_days=warn_days,
        weak_rsa_bits=2048,
    )
    config._base_dir = Path.cwd()  # noqa: SLF001
    now = utcnow()
    with tempfile.TemporaryDirectory(prefix="certclock-check-") as scratch:
        database = db or str(Path(scratch) / "check.db")
        with Inventory(database) as inventory:
            if hosts_file:
                endpoints = load_hosts(hosts_file)
                inventory.ingest(TlsCollector(endpoints, timeout=timeout).collect(), now)
            elif hosts:
                endpoints = parse_hosts("\n".join(hosts))
                inventory.ingest(TlsCollector(endpoints, timeout=timeout).collect(), now)
            if paths:
                inventory.ingest(FileCollector(paths).collect(), now)
            report = build_report(inventory, config, now)
    return evaluate(report, fail_on)


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
        "gaps": [{"source": g.source, "detail": g.detail, "message": g.message} for g in report.gaps],
    }
    return json.dumps(document, indent=2) + "\n"


def render(outcome: CheckOutcome, fmt: str) -> str:
    if fmt == "json":
        return render_json_outcome(outcome)
    if fmt == "markdown":
        return render_markdown(outcome.report)
    return render_text(outcome)
