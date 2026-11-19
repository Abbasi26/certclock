"""Evaluate an event export from a Certificate Connector for Microsoft Intune server.

Intune has no stable API for the connector health shown in the admin center
(Graph only offers the beta ``ndesConnector`` resource). The connector does
log locally, though. Microsoft documents the event log, the event source and
every event ID:

- Logging and event IDs:
  https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview#logging
- Event source ``Microsoft-Intune-CertificateConnectors``:
  https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/setup-connector

The bundled ``Get-CertClockIntuneConnector.ps1`` reads those events
read-only on the connector server and writes ID, time, level and log name.
It does not export the message text, because the events can contain device
IDs, user IDs and thumbprints. This module only reads that JSON, so it
runs offline.

Service names and the connector's own client certificate are not
evaluated: Microsoft Learn does not document them for the current
connector in a way this check could rely on.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from certclock.dates import ensure_utc, format_datetime, parse_datetime

PROVIDER = "Microsoft-Intune-CertificateConnectors"
SOURCE_URL = "https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview#logging"

SUCCESS = "success"
INFO = "info"
RETRY = "retry"
FAILURE = "failure"

# Event ID -> (name, kind). Names are copied from Microsoft Learn (link above).
EVENTS: dict[int, tuple[str, str]] = {
    # PKCS, Admin
    1000: ("PkcsRequestSuccess", SUCCESS),
    1001: ("PkcsRequestFailure", FAILURE),
    1200: ("PkcsRecryptRequestSuccess", SUCCESS),
    1201: ("PkcsRecryptRequestFailure", FAILURE),
    # PKCS, Operational
    1002: ("PkcsDownloadSuccess", SUCCESS),
    1003: ("PkcsDownloadFailure", FAILURE),
    1020: ("PkcsDownloadedRequest", INFO),
    1032: ("PkcsDigiCertRequest", INFO),
    1050: ("PkcsIssuedSuccess", SUCCESS),
    1051: ("PkcsIssuedFailedAttempt", RETRY),
    1052: ("PkcsIssuedFailure", FAILURE),
    1100: ("PkcsUploadSuccess", SUCCESS),
    1101: ("PkcsUploadFailure", FAILURE),
    1102: ("PkcsUploadedRequest", INFO),
    1202: ("PkcsRecryptDownloadSuccess", SUCCESS),
    1203: ("PkcsRecryptDownloadFailure", FAILURE),
    1220: ("PkcsRecryptDownloadedRequest", INFO),
    1250: ("PkcsRecryptReencryptSuccess", SUCCESS),
    1251: ("PkcsRecryptDecryptSuccess", SUCCESS),
    1252: ("PkcsRecryptDecryptFailure", FAILURE),
    1253: ("PkcsRecryptReencryptFailure", FAILURE),
    1300: ("PkcsRecryptUploadSuccess", SUCCESS),
    1301: ("PkcsRecryptUploadFailure", FAILURE),
    1302: ("PkcsRecryptUploadedRequest", INFO),
    # PKCS Import
    2000: ("PkcsImportRequestSuccess", SUCCESS),
    2001: ("PkcsImportRequestFailure", FAILURE),
    2202: ("PkcsImportDownloadSuccess", SUCCESS),
    2203: ("PkcsImportDownloadFailure", FAILURE),
    2020: ("PkcsImportDownloadedRequest", INFO),
    2050: ("PkcsImportReencryptSuccess", SUCCESS),
    2051: ("PkcsImportReencryptFailedAttempt", RETRY),
    2052: ("PkcsImportReencryptFailure", FAILURE),
    2100: ("PkcsImportUploadSuccess", SUCCESS),
    2101: ("PkcsImportUploadFailure", FAILURE),
    2102: ("PkcsImportUploadedRequest", INFO),
    # Revocation
    3000: ("RevokeRequestSuccess", SUCCESS),
    3001: ("RevokeRequestFailure", FAILURE),
    3002: ("RevokeDownloadSuccess", SUCCESS),
    3003: ("RevokeDownloadFailure", FAILURE),
    3020: ("RevokeDownloadedRequest", INFO),
    3032: ("RevokeDigicertRequest", INFO),
    3050: ("RevokeSuccess", SUCCESS),
    3051: ("RevokeFailure", FAILURE),
    3052: ("RevokeFailedAttempt", RETRY),
    3100: ("RevokeUploadSuccess", SUCCESS),
    3101: ("RevokeUploadFailure", FAILURE),
    3102: ("RevokeUploadedRequest", INFO),
    # SCEP ("ScrepRequestSuccess" is spelled that way on Learn)
    4000: ("ScrepRequestSuccess", SUCCESS),
    4001: ("ScepRequestIssuedFailure", FAILURE),
    4002: ("ScepRequestUploadFailure", FAILURE),
    4003: ("ScepRequestReceived", INFO),
    4004: ("ScepVerifySuccess", SUCCESS),
    4005: ("ScepVerifyFailure", FAILURE),
    4006: ("ScepIssuedSuccess", SUCCESS),
    4007: ("ScepIssuedFailure", FAILURE),
    4008: ("ScepNotifySuccess", SUCCESS),
    4009: ("ScepNotifyAttemptFailed", RETRY),
    4010: ("ScepNotifySaveToDiskFailed", FAILURE),
    # Connector health
    5000: ("HealthMessageUploadSuccess", SUCCESS),
    5001: ("HealthMessageUploadFailedAttempt", RETRY),
    5002: ("HealthMessageUploadFailure", FAILURE),
}

HEALTH_IDS = (5000, 5001, 5002)

STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_FAILURE = "failure"
EXIT_CODES = {STATUS_OK: 0, STATUS_WARNING: 1, STATUS_FAILURE: 2}


@dataclass
class ConnectorEvent:
    event_id: int
    time_created: dt.datetime
    level: str = ""
    log_name: str = ""

    @property
    def name(self) -> str:
        return EVENTS.get(self.event_id, ("unknown", INFO))[0]

    @property
    def kind(self) -> str:
        return EVENTS.get(self.event_id, ("unknown", INFO))[1]


@dataclass
class ConnectorHealth:
    host: str
    status: str
    window_hours: int
    events_in_window: int
    last_health_event: ConnectorEvent | None
    failures: dict[int, int] = field(default_factory=dict)
    retries: dict[int, int] = field(default_factory=dict)
    unknown_ids: list[int] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.status]

    def to_dict(self) -> dict:
        last = self.last_health_event
        return {
            "host": self.host,
            "status": self.status,
            "window_hours": self.window_hours,
            "events_in_window": self.events_in_window,
            "last_health_event": None
            if last is None
            else {"id": last.event_id, "name": last.name, "time_created": format_datetime(last.time_created)},
            "failures": [{"id": i, "name": EVENTS[i][0], "count": n} for i, n in sorted(self.failures.items())],
            "retries": [{"id": i, "name": EVENTS[i][0], "count": n} for i, n in sorted(self.retries.items())],
            "unknown_ids": self.unknown_ids,
            "reasons": self.reasons,
            "warnings": self.warnings,
            "source": SOURCE_URL,
            "exit_code": self.exit_code,
        }


def load_export(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8-sig")
    document = json.loads(text)
    if not isinstance(document, dict) or document.get("collector") != "certclock-intune-connector":
        raise ValueError(f"{path}: not a certclock-intune-connector export")
    return document


def parse_events(document: dict, warnings: list[str]) -> list[ConnectorEvent]:
    raw = document.get("events") or []
    if isinstance(raw, dict):
        raw = [raw]
    events: list[ConnectorEvent] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            warnings.append(f"event {index} is not an object; skipped")
            continue
        try:
            event_id = int(item["id"])
            created = parse_datetime(str(item["time_created"]))
        except (KeyError, TypeError, ValueError):
            warnings.append(f"event {index} has no valid id or time_created; skipped")
            continue
        events.append(
            ConnectorEvent(
                event_id=event_id,
                time_created=created,
                level=str(item.get("level") or ""),
                log_name=str(item.get("log_name") or ""),
            )
        )
    return events


def evaluate(document: dict, now: dt.datetime, window_hours: int = 24) -> ConnectorHealth:
    """Rate the connector from its own events.

    - failure: the newest health upload event is 5002, or a documented
      ``*Failure`` event occurred inside the window.
    - warning: the newest health upload event is 5001, a documented retry
      event occurred inside the window, no health upload event exists at all,
      or the export reports a read error.
    - ok: otherwise.
    """

    if window_hours < 1:
        raise ValueError("window_hours must be at least 1")
    now = ensure_utc(now)
    warnings: list[str] = []
    events = parse_events(document, warnings)
    for error in document.get("errors") or []:
        warnings.append(f"export: {error}")
    since = now - dt.timedelta(hours=window_hours)
    in_window = [event for event in events if since <= event.time_created <= now]

    health = [event for event in events if event.event_id in HEALTH_IDS and event.time_created <= now]
    last_health = max(health, key=lambda event: event.time_created) if health else None

    failures: dict[int, int] = {}
    retries: dict[int, int] = {}
    unknown: set[int] = set()
    for event in in_window:
        if event.event_id not in EVENTS:
            unknown.add(event.event_id)
        elif event.kind == FAILURE:
            failures[event.event_id] = failures.get(event.event_id, 0) + 1
        elif event.kind == RETRY:
            retries[event.event_id] = retries.get(event.event_id, 0) + 1

    reasons: list[str] = []
    status = STATUS_OK
    if last_health is None:
        status = STATUS_WARNING
        reasons.append("no health upload event (5000-5002) in the export")
    elif last_health.event_id == 5002:
        status = STATUS_FAILURE
        reasons.append(f"newest health upload event is 5002 HealthMessageUploadFailure ({format_datetime(last_health.time_created)})")
    elif last_health.event_id == 5001:
        status = STATUS_WARNING
        reasons.append(f"newest health upload event is 5001 HealthMessageUploadFailedAttempt ({format_datetime(last_health.time_created)})")

    window_failures = {i: n for i, n in failures.items() if i not in HEALTH_IDS}
    window_retries = {i: n for i, n in retries.items() if i not in HEALTH_IDS}
    if window_failures:
        status = STATUS_FAILURE
        listed = ", ".join(f"{i} {EVENTS[i][0]} x{n}" for i, n in sorted(window_failures.items()))
        reasons.append(f"failure events in the last {window_hours} h: {listed}")
    if window_retries:
        if status == STATUS_OK:
            status = STATUS_WARNING
        listed = ", ".join(f"{i} {EVENTS[i][0]} x{n}" for i, n in sorted(window_retries.items()))
        reasons.append(f"retry events in the last {window_hours} h: {listed}")
    if document.get("errors") and status == STATUS_OK:
        status = STATUS_WARNING
        reasons.append("the export reports read errors")

    return ConnectorHealth(
        host=str(document.get("host") or "unknown-host"),
        status=status,
        window_hours=window_hours,
        events_in_window=len(in_window),
        last_health_event=last_health,
        failures=failures,
        retries=retries,
        unknown_ids=sorted(unknown),
        reasons=reasons,
        warnings=warnings,
    )


def format_text(health: ConnectorHealth) -> str:
    lines = [
        f"Intune certificate connector on {health.host}: {health.status.upper()}",
        f"events in the last {health.window_hours} h: {health.events_in_window}",
    ]
    last = health.last_health_event
    if last is None:
        lines.append("last health upload: none in export")
    else:
        lines.append(f"last health upload: {last.event_id} {last.name} at {format_datetime(last.time_created)}")
    lines.extend(f"- {reason}" for reason in health.reasons)
    if health.unknown_ids:
        lines.append("undocumented event IDs (ignored): " + ", ".join(str(i) for i in health.unknown_ids))
    lines.extend(f"warning: {warning}" for warning in health.warnings)
    lines.append(f"event IDs: {SOURCE_URL}")
    return "\n".join(lines)
