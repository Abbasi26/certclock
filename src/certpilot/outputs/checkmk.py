"""Checkmk local-check text. The process exit code stays 0; status is in the text."""

from __future__ import annotations

from collections import Counter

from certpilot.models import Report, ReportCert


def render_checkmk(report: Report) -> str:
    names = _service_names(report.certificates)
    lines = [_summary_line(report)]
    for cert in report.certificates:
        status = _status(cert, report.warn_days, report.crit_days)
        label = _level(status)
        problems = " ".join(problem.message for problem in cert.problems) or "No findings."
        owner = cert.owner or "unassigned"
        text = (
            f"{label} - {cert.subject_cn} {_expiry_clause(cert)}. "
            f"Owner: {owner}. {problems}"
        )
        text = " ".join(text.split())
        lines.append(
            f'{status} "Cert {names[cert.fingerprint]}" '
            f"expires_in_days={cert.days_remaining};{report.warn_days};{report.crit_days};; "
            f"{text}"
        )
    return "\n".join(lines) + "\n"


def _summary_line(report: Report) -> str:
    counts = report.summary()
    worst = 0
    for cert in report.certificates:
        worst = max(worst, _status(cert, report.warn_days, report.crit_days))
    label = _level(worst)
    detail = (
        f"{label} - {counts['expired']} expired, {counts['within_7']} within 7 days, "
        f"{counts['within_30']} within 30 days, {counts['total']} total"
    )
    return (
        f'{worst} "CertPilot summary" '
        f"expired={counts['expired']}|within_7={counts['within_7']}|"
        f"within_30={counts['within_30']}|within_90={counts['within_90']}|"
        f"total={counts['total']} {detail}"
    )


def _status(cert: ReportCert, warn_days: int, crit_days: int) -> int:
    if cert.days_remaining < 0 or cert.days_remaining <= crit_days:
        return 2
    if cert.days_remaining <= warn_days:
        return 1
    return 0


def _level(status: int) -> str:
    return {0: "OK", 1: "WARN", 2: "CRIT"}.get(status, "UNKN")


def _expiry_clause(cert: ReportCert) -> str:
    days = cert.days_remaining
    if days < 0:
        n = abs(days)
        unit = "day" if n == 1 else "days"
        return f"expired {n} {unit} ago"
    if days == 0:
        return "expires in less than 1 day"
    unit = "day" if days == 1 else "days"
    return f"expires in {days} {unit}"


def _service_names(certs: list[ReportCert]) -> dict[str, str]:
    counts = Counter(cert.subject_cn for cert in certs)
    names: dict[str, str] = {}
    for cert in certs:
        base = cert.subject_cn or cert.fingerprint[:12]
        if counts[cert.subject_cn] > 1:
            base = f"{base} {cert.fingerprint[:8]}"
        names[cert.fingerprint] = " ".join(base.split()).replace('"', "'")[:80]
    return names
