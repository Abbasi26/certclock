"""HTML, ICS, Checkmk, Prometheus, CSV, and the opt-in webhook."""

from __future__ import annotations

import datetime as dt
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

import pytest

from certclock.explain import explain
from certclock.inventory import Inventory
from certclock.mint import mint
from certclock.models import CollectionResult, Observation, Report
from certclock.outputs import write_reports
from certclock.outputs.checkmk import render_checkmk
from certclock.outputs.ics import render_ics
from certclock.outputs.prometheus import render_prometheus
from certclock.outputs.webhook import payload_for, preview_document, send_webhook


def _report(tmp_path: Path, now: dt.datetime) -> Report:
    nasty = mint(
        'bad<tag>',
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=4),
    )
    expired = mint(
        "old.example.test",
        not_before=now - dt.timedelta(days=30),
        not_after=now - dt.timedelta(days=2),
    )
    month = mint(
        "month.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=20),
    )
    later = mint(
        "later.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=200),
    )
    with Inventory(tmp_path / "out.db") as inventory:
        inventory.ingest(
            CollectionResult(
                observations=[
                    Observation(source="file", detail=name, der=item.der)
                    for name, item in (
                        ("bad.pem", nasty),
                        ("old.pem", expired),
                        ("month.pem", month),
                        ("later.pem", later),
                    )
                ],
                replaced_sources=("file",),
            ),
            now,
        )
        rows = explain(inventory.certificates(), now)
    return Report(
        generated_at=now,
        certificates=rows,
        gaps=[],
        warnings=["one warning"],
        horizon_days=90,
        warn_days=30,
        crit_days=7,
        notify_within_days=30,
    )


def test_html_is_self_contained_and_escaped(tmp_path: Path, now: dt.datetime):
    report = _report(tmp_path, now)
    files = write_reports(report, tmp_path / "report")
    html = files["html"].read_text(encoding="utf-8")
    assert "bad&lt;tag&gt;" in html
    assert "<tag>" not in html
    assert "Within 7 days" in html
    assert "Within 30 days" in html
    assert "Within 90 days" in html
    assert 'src="http' not in html
    assert "stylesheet" not in html
    assert "one warning" in html
    assert files["webhook_preview"].read_text(encoding="utf-8")
    preview = json.loads(files["webhook_preview"].read_text(encoding="utf-8"))
    assert preview["sent"] is False


def test_ics_has_reminders_and_folds_long_lines(tmp_path: Path, now: dt.datetime):
    text = render_ics(_report(tmp_path, now))
    assert "BEGIN:VCALENDAR" in text
    assert text.count("BEGIN:VALARM") == 9  # 3 events inside 90 days, 3 alarms each; later is excluded
    assert "TRIGGER:-P30D" in text
    assert "TRIGGER:-P7D" in text
    assert "TRIGGER:-P1D" in text
    for line in text.split("\r\n"):
        assert len(line.encode("utf-8")) <= 75


def test_checkmk_and_prometheus(tmp_path: Path, now: dt.datetime):
    report = _report(tmp_path, now)
    checkmk = render_checkmk(report)
    assert '2 "Cert old.example.test"' in checkmk
    assert '1 "Cert month.example.test"' in checkmk
    assert '0 "Cert later.example.test"' in checkmk
    assert '2 "CertClock summary"' in checkmk
    prom = render_prometheus(report)
    assert "certclock_certificate_days_remaining{" in prom
    assert 'bucket="expired"' in prom
    assert 'code="expired"' in prom
    csv_text = (tmp_path / "unused").as_posix()
    document = json.loads(
        __import__("certclock.outputs.tabular", fromlist=["render_json"]).render_json(report)
    )
    assert document["summary"]["expired"] == 1
    from certclock.outputs.tabular import render_csv

    csv_text = render_csv(report)
    assert "old.example.test" in csv_text
    assert "days_remaining" in csv_text.splitlines()[0]


def test_webhook_preview_does_not_send(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, now: dt.datetime):
    def explode(*args, **kwargs):
        raise AssertionError("preview must not open a socket")

    monkeypatch.setattr("urllib.request.urlopen", explode)
    preview = preview_document(_report(tmp_path, now))
    assert preview["sent"] is False
    assert "old.example.test" in preview["slack"]["text"]
    assert preview["teams"]["@type"] == "MessageCard"


def test_webhook_send_and_scheme_guard(tmp_path: Path, now: dt.datetime):
    report = _report(tmp_path, now)
    with pytest.raises(ValueError, match="http"):
        send_webhook("file:///tmp/certclock-should-not-write", payload_for(report, "generic"))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib name
            length = int(self.headers.get("Content-Length", "0"))
            Handler.body = self.rfile.read(length)
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        status = send_webhook(
            f"http://127.0.0.1:{port}/hook",
            payload_for(report, "generic"),
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert status == 204
    body = json.loads(Handler.body)
    assert body["tool"] == "certclock"
    names = {item["common_name"] for item in body["certificates"]}
    assert "later.example.test" not in names
    assert "old.example.test" in names


@pytest.mark.parametrize("newline", ["\r", "\n", "\r\n"])
def test_ics_normalizes_text_newlines(
    tmp_path: Path, now: dt.datetime, newline: str
):
    report = _report(tmp_path, now)
    cert = next(cert for cert in report.certificates if cert.days_remaining == 4)
    cert.subject_cn = f"before{newline}after\\,;"

    text = render_ics(report)
    unfolded = text.replace("\r\n ", "")

    assert (
        r"SUMMARY:Certificate expires: before\nafter\\\,\;" + "\r\n"
        in unfolded
    )
    without_delimiters = text.replace("\r\n", "")
    assert "\r" not in without_delimiters
    assert "\n" not in without_delimiters
    assert all(len(line.encode("utf-8")) <= 75 for line in text.split("\r\n"))


@pytest.mark.parametrize("whitespace", ["\r", "\n", "\r\n", "\t"])
def test_checkmk_service_names_normalize_whitespace(
    tmp_path: Path, now: dt.datetime, whitespace: str
):
    report = _report(tmp_path, now)
    cert = next(cert for cert in report.certificates if cert.days_remaining == 4)
    cert.subject_cn = f"before{whitespace}after"

    text = render_checkmk(report)
    lines = text.splitlines()

    assert len(lines) == len(report.certificates) + 1
    assert "\r" not in text
    assert "\t" not in text
    assert sum(
        line.startswith(
            '2 "Cert before after" expires_in_days=4;30;7;; '
        )
        for line in lines
    ) == 1


def test_written_ics_preserves_renderer_bytes(tmp_path: Path, now: dt.datetime):
    report = _report(tmp_path, now)

    files = write_reports(report, tmp_path / "report")
    data = files["ics"].read_bytes()

    assert data == render_ics(report).encode("utf-8")
    assert b"\r\r\n" not in data
    assert data.endswith(b"\r\n")
