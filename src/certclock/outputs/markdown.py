"""Markdown summary for pull requests, issues, wikis, and chat tools that render Markdown."""

from __future__ import annotations

from certclock.dates import format_datetime
from certclock.models import Report, ReportCert

_BUCKET_LABELS = {
    "expired": "Expired",
    "within_7": "Within 7 days",
    "within_30": "Within 30 days",
    "within_90": "Within 90 days",
    "later": "Later",
}


def render_markdown(report: Report, *, limit: int | None = 50) -> str:
    """Return a GitHub-flavoured Markdown report.

    ``limit`` caps the certificate table so the text stays postable. ``None``
    lists every certificate.
    """
    counts = report.summary()
    lines = [
        "# CertClock report",
        "",
        f"Generated {format_datetime(report.generated_at)}. "
        f"WARN at {report.warn_days} days, CRIT at {report.crit_days} days.",
        "",
        "| Bucket | Certificates |",
        "| --- | ---: |",
    ]
    for bucket, label in _BUCKET_LABELS.items():
        lines.append(f"| {label} | {counts[bucket]} |")
    lines.append(f"| **Total** | **{counts['total']}** |")
    lines.append("")

    ordered = sorted(report.certificates, key=lambda cert: (cert.days_remaining, cert.subject_cn))
    shown = ordered if limit is None else ordered[:limit]
    if shown:
        lines += [
            "## Certificates by expiry",
            "",
            "| Status | Common name | Issuing CA | Days left | Expires | Owner | Findings |",
            "| --- | --- | --- | ---: | --- | --- | --- |",
        ]
        for cert in shown:
            lines.append(
                "| "
                + " | ".join(
                    [
                        status_label(cert, report.warn_days, report.crit_days),
                        _cell(cert.subject_cn or cert.fingerprint[:16]),
                        _cell(cert.issuer or "-"),
                        str(cert.days_remaining),
                        format_datetime(cert.not_after)[:10],
                        _cell(cert.owner or "unassigned"),
                        _cell(", ".join(problem.code for problem in cert.problems) or "-"),
                    ]
                )
                + " |"
            )
        if limit is not None and len(ordered) > limit:
            lines.append("")
            lines.append(f"_{len(ordered) - limit} more certificates not shown. See inventory.csv._")
        lines.append("")

    if report.gaps:
        lines += ["## Gaps", ""]
        for gap in report.gaps:
            lines.append(f"- `{_cell(gap.source)}` {_cell(gap.detail)}: {_cell(gap.message)}")
        lines.append("")
    if report.warnings:
        lines += ["## Warnings", ""]
        lines += [f"- {_cell(warning)}" for warning in report.warnings]
        lines.append("")
    return "\n".join(lines)


def status_code(cert: ReportCert, warn_days: int, crit_days: int) -> int:
    """0 OK, 1 WARN, 2 CRIT. Same thresholds as the Checkmk output."""
    if cert.days_remaining < 0 or cert.days_remaining <= crit_days:
        return 2
    if cert.days_remaining <= warn_days:
        return 1
    return 0


def status_label(cert: ReportCert, warn_days: int, crit_days: int) -> str:
    return {0: "OK", 1: "WARN", 2: "CRIT"}[status_code(cert, warn_days, crit_days)]


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")
