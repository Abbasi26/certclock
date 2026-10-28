"""Prometheus textfile snapshot. A cron job rewrites the file; CertClock is not scraped."""

from __future__ import annotations

from certclock.dates import ensure_utc
from certclock.models import Report


def render_prometheus(report: Report) -> str:
    lines = [
        "# CertClock textfile snapshot. Rewrite this file on a schedule.",
        "# HELP certclock_certificates Certificates in the latest local snapshot.",
        "# TYPE certclock_certificates gauge",
    ]
    counts = report.summary()
    for bucket, count in counts.items():
        if bucket == "total":
            continue
        lines.append(f'certclock_certificates{{bucket="{bucket}"}} {count}')
    lines.append(f'certclock_certificates{{bucket="total"}} {counts["total"]}')
    lines.extend(
        [
            "# HELP certclock_certificate_days_remaining Days until expiry. Negative means expired.",
            "# TYPE certclock_certificate_days_remaining gauge",
            "# HELP certclock_certificate_not_after_seconds Unix time when the certificate expires.",
            "# TYPE certclock_certificate_not_after_seconds gauge",
            "# HELP certclock_certificate_problem 1 when the certificate has this finding.",
            "# TYPE certclock_certificate_problem gauge",
        ]
    )
    for cert in report.certificates:
        labels = _labels(
            {
                "fingerprint": cert.fingerprint,
                "cn": cert.subject_cn,
                "owner": cert.owner or "unassigned",
                "service": cert.service or "untagged",
                "bucket": cert.bucket,
            }
        )
        expires = int(ensure_utc(cert.not_after).timestamp())
        lines.append(f"certclock_certificate_days_remaining{{{labels}}} {cert.days_remaining}")
        lines.append(f"certclock_certificate_not_after_seconds{{{labels}}} {expires}")
        for problem in cert.problems:
            problem_labels = _labels(
                {
                    "fingerprint": cert.fingerprint,
                    "cn": cert.subject_cn,
                    "code": problem.code,
                }
            )
            lines.append(f"certclock_certificate_problem{{{problem_labels}}} 1")
    return "\n".join(lines) + "\n"


def _labels(pairs: dict[str, str]) -> str:
    return ",".join(f'{key}="{_escape(value)}"' for key, value in pairs.items())


def _escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )
