import datetime as dt
import json
from pathlib import Path

import pytest

from certclock.cli import main
from certclock.intune_connector import EVENTS, evaluate, load_export

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "intune-connector.json"
NOW = dt.datetime(2026, 11, 3, 6, 0, tzinfo=dt.timezone.utc)


def _doc(*events, errors=None):
    return {
        "collector": "certclock-intune-connector",
        "version": 1,
        "host": "unit.example.test",
        "events": [{"id": i, "time_created": t} for i, t in events],
        "errors": errors or [],
    }


def test_example_is_a_failure():
    health = evaluate(load_export(EXAMPLE), NOW)
    assert health.status == "failure"
    assert health.exit_code == 2
    assert health.last_health_event.event_id == 5002
    assert health.failures == {1052: 1, 5002: 1}
    assert health.retries == {4009: 1, 5001: 1}


def test_healthy_connector_is_ok():
    health = evaluate(_doc((5001, "2026-11-03T04:00:00Z"), (5000, "2026-11-03T05:00:00Z"), (4006, "2026-11-03T05:10:00Z")), NOW)
    assert health.status == "ok"
    assert health.exit_code == 0
    assert health.reasons == []


def test_newest_health_retry_is_a_warning():
    health = evaluate(_doc((5000, "2026-11-03T04:00:00Z"), (5001, "2026-11-03T05:00:00Z")), NOW)
    assert health.status == "warning"


def test_no_health_event_is_a_warning():
    health = evaluate(_doc((4006, "2026-11-03T05:10:00Z")), NOW)
    assert health.status == "warning"
    assert "no health upload event" in health.reasons[0]


def test_failures_outside_the_window_are_ignored():
    health = evaluate(_doc((1052, "2026-11-01T01:00:00Z"), (5000, "2026-11-03T05:00:00Z")), NOW, window_hours=24)
    assert health.status == "ok"
    health = evaluate(_doc((1052, "2026-11-01T01:00:00Z"), (5000, "2026-11-03T05:00:00Z")), NOW, window_hours=72)
    assert health.status == "failure"


def test_unknown_ids_and_bad_rows_do_not_change_status():
    doc = _doc((5000, "2026-11-03T05:00:00Z"), (9999, "2026-11-03T05:01:00Z"))
    doc["events"].append({"id": "x"})
    health = evaluate(doc, NOW)
    assert health.status == "ok"
    assert health.unknown_ids == [9999]
    assert health.warnings


def test_export_errors_are_a_warning():
    health = evaluate(_doc((5000, "2026-11-03T05:00:00Z"), errors=["access denied"]), NOW)
    assert health.status == "warning"


def test_wrong_document_is_refused(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"collector": "certclock-windows-store"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_export(path)


def test_event_table_matches_learn_ranges():
    for event_id, (name, kind) in EVENTS.items():
        assert 1000 <= event_id <= 5999
        assert kind in {"success", "info", "retry", "failure"}
        if "Failure" in name or name.endswith("SaveToDiskFailed"):
            assert kind == "failure", name
        if "FailedAttempt" in name or "AttemptFailed" in name:
            assert kind == "retry", name


def test_cli_json(capsys):
    code = main(["intune-connector", "--path", str(EXAMPLE), "--as-of", "2026-11-03T06:00:00Z", "--format", "json"])
    assert code == 2
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "failure"
    assert out["last_health_event"]["name"] == "HealthMessageUploadFailure"
    assert out["source"].startswith("https://learn.microsoft.com/")


def test_cli_text(capsys):
    code = main(["intune-connector", "--path", str(EXAMPLE), "--as-of", "2026-11-03T06:00:00Z"])
    assert code == 2
    assert "FAILURE" in capsys.readouterr().out
