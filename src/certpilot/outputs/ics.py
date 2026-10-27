"""iCalendar export with 30-day, 7-day, and 1-day reminders."""

from __future__ import annotations

from datetime import timedelta

from certpilot import __version__
from certpilot.dates import ensure_utc, format_date
from certpilot.explain import source_label
from certpilot.models import Report, ReportCert


def render_ics(report: Report) -> str:
    stamp = ensure_utc(report.generated_at).strftime("%Y%m%dT%H%M%SZ")
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        f"PRODID:-//Wasaf Abbasi//CertPilot {__version__}//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "X-WR-CALNAME:CertPilot certificate expiries",
    ]
    for cert in report.certificates:
        if cert.days_remaining > report.horizon_days:
            continue
        lines.extend(_event(cert, stamp))
    lines.append("END:VCALENDAR")
    return "\r\n".join(_fold(line) for line in lines) + "\r\n"


def _event(cert: ReportCert, stamp: str) -> list[str]:
    start = ensure_utc(cert.not_after)
    begin_stamp = start.strftime("%Y%m%dT%H%M%SZ")
    end_stamp = (start + timedelta(hours=1)).strftime("%Y%m%dT%H%M%SZ")
    prefix = "EXPIRED: " if cert.days_remaining < 0 else ""
    summary = f"{prefix}Certificate expires: {cert.subject_cn}"
    description = _description(cert)
    uid = "certpilot-" + cert.fingerprint.replace(":", "") + "@localhost"
    lines = [
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{stamp}",
        f"DTSTART:{begin_stamp}",
        f"DTEND:{end_stamp}",
        f"SUMMARY:{_escape(summary)}",
        f"DESCRIPTION:{_escape(description)}",
    ]
    for days, label in ((30, "30 days"), (7, "7 days"), (1, "1 day")):
        lines.extend(
            [
                "BEGIN:VALARM",
                f"TRIGGER:-P{days}D",
                "ACTION:DISPLAY",
                f"DESCRIPTION:{_escape(label + ' until ' + cert.subject_cn + ' expires')}",
                "END:VALARM",
            ]
        )
    lines.append("END:VEVENT")
    return lines


def _description(cert: ReportCert) -> str:
    parts = [
        f"{cert.subject_cn} expires on {format_date(cert.not_after)}.",
        f"Issuer: {cert.issuer}.",
        f"Owner: {cert.owner or 'unassigned'}. Service: {cert.service or 'untagged'}.",
    ]
    if cert.dependency_note:
        parts.append(cert.dependency_note)
    if cert.problems:
        parts.append("Findings: " + " ".join(problem.message for problem in cert.problems))
    sources = ", ".join(f"{source_label(obs.source)} {obs.detail}" for obs in cert.sources)
    if sources:
        parts.append("Seen at: " + sources + ".")
    return " ".join(parts)


def _escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("\r\n", "\n")
        .replace("\n", "\\n")
        .replace(",", "\\,")
        .replace(";", "\\;")
    )


def _fold(line: str) -> str:
    chunks: list[str] = []
    first = True
    data = line
    while data:
        limit = 75 if first else 74
        if len(data.encode("utf-8")) <= limit:
            chunks.append(data if first else " " + data)
            break
        taken = 0
        size = 0
        for char in data:
            width = len(char.encode("utf-8"))
            if size + width > limit:
                break
            size += width
            taken += 1
        if taken == 0:
            taken = 1
        piece = data[:taken]
        data = data[taken:]
        chunks.append(piece if first else " " + piece)
        first = False
    return "\r\n".join(chunks)
