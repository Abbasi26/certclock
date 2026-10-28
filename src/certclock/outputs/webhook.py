"""Optional webhook notification. Nothing is sent unless ``send`` is called."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from certclock import __version__
from certclock.dates import format_datetime
from certclock.models import Report, ReportCert

_FORMATS = ("generic", "slack", "teams")


def certificates_in_window(report: Report) -> list[ReportCert]:
    return [
        cert
        for cert in report.certificates
        if cert.days_remaining <= report.notify_within_days
    ]


def generic_payload(report: Report) -> dict:
    chosen = certificates_in_window(report)
    counts = report.summary()
    return {
        "tool": "certclock",
        "version": __version__,
        "generated_at": format_datetime(report.generated_at),
        "notify_within_days": report.notify_within_days,
        "summary": counts,
        "gaps": [
            {"source": gap.source, "detail": gap.detail, "message": gap.message}
            for gap in report.gaps
        ],
        "certificates": [
            {
                "fingerprint": cert.fingerprint,
                "common_name": cert.subject_cn,
                "not_after": format_datetime(cert.not_after),
                "days_remaining": cert.days_remaining,
                "bucket": cert.bucket,
                "owner": cert.owner,
                "service": cert.service,
                "dependency_note": cert.dependency_note,
                "problems": [problem.message for problem in cert.problems],
            }
            for cert in chosen
        ],
    }


def slack_payload(report: Report) -> dict:
    return {"text": _text(report)}


def teams_payload(report: Report) -> dict:
    counts = report.summary()
    urgent = len(certificates_in_window(report))
    color = "9d2c2c" if counts["expired"] or urgent else "0f6e6b"
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": "CertClock certificate expiries",
        "title": f"CertClock: {urgent} certificate(s) inside {report.notify_within_days} days",
        "text": _text(report),
    }


def preview_document(report: Report) -> dict:
    return {
        "sent": False,
        "note": "Preview only. CertClock does not send a webhook unless you pass --send.",
        "generic": generic_payload(report),
        "slack": slack_payload(report),
        "teams": teams_payload(report),
    }


def payload_for(report: Report, fmt: str) -> dict:
    if fmt not in _FORMATS:
        raise ValueError(f"webhook format must be one of: {', '.join(_FORMATS)}")
    if fmt == "slack":
        return slack_payload(report)
    if fmt == "teams":
        return teams_payload(report)
    return generic_payload(report)


def send_webhook(url: str, payload: dict, timeout: float = 15.0) -> int:
    """POST JSON. Returns the HTTP status. Refuses non-HTTP URLs."""

    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("webhook URL must start with http:// or https://")
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"CertClock/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"webhook returned HTTP {exc.code}: {detail}") from exc


def _text(report: Report) -> str:
    chosen = certificates_in_window(report)
    counts = report.summary()
    lines = [
        f"CertClock {__version__}: {counts['expired']} expired, "
        f"{len(chosen)} inside {report.notify_within_days} days "
        f"({counts['total']} in inventory)."
    ]
    for cert in chosen[:20]:
        owner = cert.owner or "unassigned"
        if cert.days_remaining < 0:
            when = f"expired {abs(cert.days_remaining)} days ago"
        elif cert.days_remaining == 0:
            when = "expires in less than 1 day"
        else:
            when = f"expires in {cert.days_remaining} days"
        lines.append(f"- {cert.subject_cn} {when} ({owner})")
    remaining = len(chosen) - 20
    if remaining > 0:
        lines.append(f"- … and {remaining} more")
    if report.gaps:
        lines.append(f"{len(report.gaps)} source(s) could not be read.")
    return "\n".join(lines)
