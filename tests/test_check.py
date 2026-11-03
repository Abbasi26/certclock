"""`certclock check` exit codes and the Markdown report."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from certclock.check import EXIT_CRIT, EXIT_ERROR, EXIT_OK, EXIT_WARN, run_check
from certclock.cli import main
from certclock.dates import utcnow
from certclock.localtls import LocalTlsServer
from certclock.mint import mint


def _cert_file(directory: Path, name: str, days: int) -> Path:
    now = utcnow()
    minted = mint(
        name,
        not_before=now - dt.timedelta(days=5),
        not_after=now + dt.timedelta(days=days, hours=12),
    )
    path = directory / f"{name}.pem"
    path.write_bytes(minted.pem)
    return path


def test_check_ok_when_everything_is_far_out(tmp_path: Path, capsys):
    _cert_file(tmp_path, "far.example.test", 200)
    assert main(["check", "--path", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("OK: 1 certificates")


def test_check_warn_only_fails_with_fail_on_warn(tmp_path: Path, capsys):
    _cert_file(tmp_path, "soon.example.test", 20)
    assert main(["check", "--path", str(tmp_path)]) == EXIT_OK
    assert main(["check", "--path", str(tmp_path), "--fail-on", "warn"]) == EXIT_WARN
    out = capsys.readouterr().out
    assert "WARN" in out and "soon.example.test" in out


def test_check_crit_and_expired_fail(tmp_path: Path, capsys):
    _cert_file(tmp_path, "soon.example.test", 20)
    _cert_file(tmp_path, "gone.example.test", -3)
    assert main(["check", "--path", str(tmp_path), "--format", "json"]) == EXIT_CRIT
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "crit"
    assert document["exit_code"] == EXIT_CRIT
    names = [item["common_name"] for item in document["flagged"]]
    assert names == ["gone.example.test", "soon.example.test"]
    assert document["flagged"][0]["days_remaining"] < 0


def test_check_fail_on_never_always_exits_zero(tmp_path: Path):
    _cert_file(tmp_path, "gone.example.test", -3)
    assert main(["check", "--path", str(tmp_path), "--fail-on", "never"]) == EXIT_OK


def test_check_custom_thresholds(tmp_path: Path):
    _cert_file(tmp_path, "mid.example.test", 45)
    assert main(["check", "--path", str(tmp_path), "--fail-on", "warn"]) == EXIT_OK
    assert main(["check", "--path", str(tmp_path), "--warn-days", "60", "--fail-on", "warn"]) == EXIT_WARN
    assert main(["check", "--path", str(tmp_path), "--warn-days", "60", "--crit-days", "50"]) == EXIT_CRIT


def test_check_usage_errors_exit_3(tmp_path: Path, capsys):
    assert main(["check"]) == EXIT_ERROR
    assert main(["check", "--path", str(tmp_path), "--warn-days", "5", "--crit-days", "10"]) == EXIT_ERROR
    assert main(["check", "--host", "bad:port:x"]) == EXIT_ERROR
    assert "certclock:" in capsys.readouterr().err


def test_check_reads_loopback_tls(tmp_path: Path, capsys):
    now = utcnow()
    minted = mint(
        "edge.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=3, hours=1),
    )
    with LocalTlsServer(minted.pem, minted.key_pem) as server:
        code = main(["check", "--host", f"127.0.0.1:{server.port} edge.example.test", "--timeout", "5"])
    assert code == EXIT_CRIT
    assert "edge.example.test" in capsys.readouterr().out


def test_check_against_existing_db_with_markdown(tmp_path: Path, capsys):
    demo = tmp_path / "demo"
    assert main(["demo", "--offline", "--out", str(demo)]) == 0
    capsys.readouterr()
    db_path = demo / "certclock.db"
    db_size = db_path.stat().st_size
    db_mtime = db_path.stat().st_mtime
    assert main(["check", "--db", str(db_path), "--format", "markdown"]) == EXIT_CRIT
    out = capsys.readouterr().out
    assert out.startswith("# CertClock report")
    assert "| Expired |" in out
    assert "| CRIT |" in out
    # DB unchanged
    assert db_path.stat().st_size == db_size
    assert db_path.stat().st_mtime == db_mtime


def test_report_writes_markdown_file(tmp_path: Path):
    demo = tmp_path / "demo"
    assert main(["demo", "--offline", "--out", str(demo)]) == 0
    out = tmp_path / "out"
    assert main(["report", "--db", str(demo / "certclock.db"), "--out", str(out)]) == 0
    text = (out / "report.md").read_text(encoding="utf-8")
    assert "## Certificates by expiry" in text
    assert "BEGIN" not in text


def test_markdown_escapes_pipes_and_limits_rows(tmp_path: Path):
    from certclock.outputs.markdown import render_markdown
    from certclock.models import Report, ReportCert

    now = utcnow()

    def cert(i: int) -> ReportCert:
        return ReportCert(
            fingerprint=f"{i:064x}", serial="1", subject=f"CN=a|b{i}", subject_cn=f"a|b{i}",
            issuer="CN=x", not_before=now, not_after=now + dt.timedelta(days=i), days_remaining=i,
            bucket="later", sans=[], key_type="ec", key_size=256, signature_algorithm="sha256",
            self_signed=True, is_ca=False, owner=None, service=None, owner_note=None,
            dependency_note=None, problems=[], sources=[],
        )

    report = Report(now, [cert(100 + i) for i in range(5)], [], [], 90, 30, 7, 30)
    text = render_markdown(report, limit=2)
    assert "a\\|b100" in text
    assert "3 more certificates not shown" in text


@pytest.mark.parametrize("fmt", ["text", "json", "markdown"])
def test_check_formats_do_not_leak_keys(tmp_path: Path, capsys, fmt: str):
    now = utcnow()
    minted = mint("bundle.example.test", not_before=now, not_after=now + dt.timedelta(days=2))
    (tmp_path / "bundle.pem").write_bytes(minted.pem + minted.key_pem)
    main(["check", "--path", str(tmp_path), "--format", fmt])
    assert "PRIVATE KEY" not in capsys.readouterr().out


def test_check_db_read_only_no_host_path(tmp_path: Path, capsys):
    """--db alone reads production DB and never writes to it."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0
    prod_size = prod_db.stat().st_size
    prod_mtime = prod_db.stat().st_mtime

    # Run check --db only
    assert main(["check", "--db", str(prod_db)]) == EXIT_OK

    # DB unchanged
    assert prod_db.stat().st_size == prod_size
    assert prod_db.stat().st_mtime == prod_mtime


def test_check_db_with_host_does_not_write_prod_db(tmp_path: Path, capsys):
    """--db with --host merges in memory; production DB untouched."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0
    prod_size = prod_db.stat().st_size
    prod_mtime = prod_db.stat().st_mtime

    now = utcnow()
    minted = mint("edge.example.test", not_before=now - dt.timedelta(days=1), not_after=now + dt.timedelta(days=3))
    with LocalTlsServer(minted.pem, minted.key_pem) as server:
        code = main(["check", "--db", str(prod_db), "--host", f"127.0.0.1:{server.port} edge.example.test", "--timeout", "5"])
    assert code == EXIT_CRIT  # edge cert is within 7 days

    # Production DB unchanged
    assert prod_db.stat().st_size == prod_size
    assert prod_db.stat().st_mtime == prod_mtime


def test_check_db_with_path_does_not_write_prod_db(tmp_path: Path, capsys):
    """--db with --path merges in memory; production DB untouched."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0
    prod_size = prod_db.stat().st_size

    _cert_file(tmp_path, "soon.example.test", 20)
    assert main(["check", "--db", str(prod_db), "--path", str(tmp_path / "soon.example.test.pem"), "--fail-on", "warn"]) == EXIT_WARN

    assert prod_db.stat().st_size == prod_size


def test_check_db_merge_preserves_both_gaps_and_warnings(tmp_path: Path):
    """Gaps and warnings from both prod and temp DB appear in report."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0

    # Unreachable host to create a gap in temp collection
    bad_host = "127.0.0.1:9999"
    outcome = run_check(db=str(prod_db), hosts=[bad_host], paths=[], fail_on="never", timeout=0.1)
    report = outcome.report

    # Prod cert present
    assert any(c.subject_cn == "prod.example.test" for c in report.certificates)
    # Gap from unreachable host present
    assert any(g.source == "tls" and bad_host in g.detail for g in report.gaps)


def test_check_without_db_still_uses_temp_db(tmp_path: Path, capsys):
    """No --db: current behaviour unchanged (temp DB only)."""
    _cert_file(tmp_path, "far.example.test", 200)
    assert main(["check", "--path", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("OK: 1 certificates")
