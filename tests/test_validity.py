"""Validity-period findings and the CA/Browser Forum schedule (Ballot SC-081v3)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from certclock.cli import main
from certclock.collectors.adcs import AdcsCollector
from certclock.config import load_config
from certclock.dates import utcnow
from certclock.explain import br_max_validity_days, explain, validity_days
from certclock.inventory import Inventory
from certclock.mint import mint
from certclock.models import StoredCert, StoredObs

UTC = dt.timezone.utc


def _stored(
    not_before: dt.datetime,
    days: float,
    *,
    is_ca: bool | None = False,
    detail: str = "file a.pem",
    source: str = "file",
) -> StoredCert:
    return StoredCert(
        fingerprint="ab" * 32,
        kind="leaf",
        serial="01",
        serial_normalized="01",
        subject="CN=app.example.test",
        subject_cn="app.example.test",
        subject_normalized="cn=app.example.test",
        issuer="CN=app.example.test",
        issuer_normalized="cn=app.example.test",
        not_before=not_before,
        not_after=not_before + dt.timedelta(days=days) - dt.timedelta(seconds=1),
        sans=["app.example.test"],
        key_type="EC",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        self_signed=False,
        is_ca=is_ca,
        subject_key_id=None,
        authority_key_id=None,
        observations=[
            StoredObs(
                source=source,
                detail=detail,
                collected_at=not_before,
                requested_name=None,
                name_matches=None,
                chain_seen=False,
                chain_fingerprints=[],
            )
        ],
    )


def _long(cert: StoredCert, max_days: int = 100):
    now = cert.not_before + dt.timedelta(days=1)
    row = explain([cert], now, max_validity_days=max_days)[0]
    return [problem for problem in row.problems if problem.code == "long_validity"]


@pytest.mark.parametrize(
    ("issued", "expected"),
    [
        (dt.datetime(2026, 3, 14, 23, 59, 59, tzinfo=UTC), 398),
        (dt.datetime(2026, 3, 15, tzinfo=UTC), 200),
        (dt.datetime(2027, 3, 14, 23, 59, 59, tzinfo=UTC), 200),
        (dt.datetime(2027, 3, 15, tzinfo=UTC), 100),
        (dt.datetime(2029, 3, 14, 23, 59, 59, tzinfo=UTC), 100),
        (dt.datetime(2029, 3, 15, tzinfo=UTC), 47),
        (dt.datetime(2020, 1, 1), 398),
    ],
)
def test_br_schedule_by_issue_date(issued: dt.datetime, expected: int):
    assert br_max_validity_days(issued) == expected


def test_validity_counts_inclusively():
    start = dt.datetime(2026, 11, 1, tzinfo=UTC)
    assert validity_days(start, start + dt.timedelta(days=100) - dt.timedelta(seconds=1)) == 100


def test_threshold_is_exclusive_and_configurable():
    start = dt.datetime(2026, 11, 1, tzinfo=UTC)
    assert _long(_stored(start, 100)) == []
    assert len(_long(_stored(start, 101))) == 1
    assert _long(_stored(start, 101), max_days=200) == []
    assert _long(_stored(start, 5000), max_days=0) == []


def test_message_names_the_br_tier_and_later_steps():
    within = _long(_stored(dt.datetime(2026, 11, 1, tzinfo=UTC), 180))[0].message
    assert "valid for 180 days" in within
    assert "maximum is 200 days" in within
    assert "100 days for certificates issued from 15 Mar 2027" in within
    assert "47 days for certificates issued from 15 Mar 2029" in within

    over = _long(_stored(dt.datetime(2026, 11, 1, tzinfo=UTC), 215))[0].message
    assert "exceeds the 200-day maximum" in over

    late = _long(_stored(dt.datetime(2029, 4, 1, tzinfo=UTC), 60), max_days=40)[0].message
    assert "exceeds the 47-day maximum" in late
    assert "falls to" not in late


def test_ca_certificates_are_not_flagged():
    start = dt.datetime(2026, 11, 1, tzinfo=UTC)
    assert _long(_stored(start, 3650, is_ca=True)) == []
    assert len(_long(_stored(start, 3650, is_ca=None))) == 1


def test_adcs_template_is_named():
    cert = _stored(
        dt.datetime(2026, 10, 1, tzinfo=UTC),
        730,
        source="adcs",
        detail="request 7 template Example Web Server requester EXAMPLE\\svc-web",
    )
    message = _long(cert)[0].message
    assert 'ADCS certificate template "Example Web Server"' in message


def test_adcs_csv_end_to_end(tmp_path: Path, now: dt.datetime):
    csv_path = tmp_path / "issued.csv"
    csv_path.write_text(
        "Request ID,Requester Name,Request Common Name,Request Disposition,Certificate Template,"
        "Serial Number,Certificate Effective Date,Certificate Expiration Date,Issuer Name\n"
        "11,EXAMPLE\\svc-enroll,long.example.test,20,ExampleUser2y,0a11,"
        "2026-10-01T00:00:00Z,2028-10-01T00:00:00Z,CN=Example Laboratory Issuing CA\n"
        "12,EXAMPLE\\svc-enroll,short.example.test,20,ExampleUser90d,0a12,"
        "2026-10-01T00:00:00Z,2026-12-30T00:00:00Z,CN=Example Laboratory Issuing CA\n",
        encoding="utf-8",
    )
    collector = AdcsCollector([{"path": str(csv_path), "issuer": "CN=Example Laboratory Issuing CA"}])
    with Inventory(tmp_path / "inv.db") as inventory:
        inventory.ingest(collector.collect(), now)
        rows = explain(inventory.certificates(), now, max_validity_days=100)
    flagged = {
        row.subject_cn: problem.message
        for row in rows
        for problem in row.problems
        if problem.code == "long_validity"
    }
    assert list(flagged) == ["long.example.test"]
    assert '"ExampleUser2y"' in flagged["long.example.test"]


def test_config_key_and_validation(tmp_path: Path):
    path = tmp_path / "certclock.yml"
    path.write_text("max_validity_days: 47\n", encoding="utf-8")
    assert load_config(path).max_validity_days == 47
    path.write_text("max_validity_days: -1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)
    path.write_text("horizon_days: 90\n", encoding="utf-8")
    assert load_config(path).max_validity_days == 100


def test_check_lists_long_validity_without_changing_exit_code(tmp_path: Path, capsys):
    start = utcnow() - dt.timedelta(days=5)
    minted = mint("long.example.test", not_before=start, not_after=start + dt.timedelta(days=300))
    (tmp_path / "long.pem").write_bytes(minted.pem)

    assert main(["check", "--path", str(tmp_path), "--fail-on", "warn"]) == 0
    assert "LONG long.example.test" in capsys.readouterr().out

    assert main(["check", "--path", str(tmp_path), "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert [item["common_name"] for item in document["long_validity"]] == ["long.example.test"]

    assert main(["check", "--path", str(tmp_path), "--max-validity-days", "0"]) == 0
    assert "LONG" not in capsys.readouterr().out
