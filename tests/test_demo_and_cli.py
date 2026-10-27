"""Demo, scan, and the collector scripts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from certpilot.cli import main
from certpilot.demo import run_demo


def test_demo_offline_is_fast_and_keeps_keys_out(tmp_path: Path):
    result = run_demo(tmp_path / "demo", live=False)
    assert result.elapsed_seconds < 60
    summary = result.summary
    assert summary["expired"] >= 1
    assert summary["within_7"] >= 1
    assert summary["within_30"] >= 1
    assert summary["within_90"] >= 1
    assert summary["later"] >= 1
    assert result.problem_counts["weak_key"] >= 1
    assert result.problem_counts["sha1"] >= 1
    assert result.problem_counts["self_signed"] >= 1
    assert result.problem_counts["issuer_expires_first"] >= 1
    assert result.problem_counts["issuer_not_in_inventory"] >= 1
    assert "san_mismatch" not in result.problem_counts
    assert result.warnings >= 2
    text = _outputs(result.output_dir)
    assert "BEGIN PRIVATE KEY" not in text
    assert "BEGIN EC PRIVATE KEY" not in text
    assert "BEGIN RSA PRIVATE KEY" not in text
    assert ".work" not in text
    assert "laptop-enroll.example.test" in text
    assert "revoked.example.test" not in text
    preview = json.loads((result.output_dir / "webhook-preview.json").read_text(encoding="utf-8"))
    assert preview["sent"] is False
    inventory = json.loads((result.output_dir / "inventory.json").read_text(encoding="utf-8"))
    mail = next(item for item in inventory["certificates"] if item["common_name"] == "mail.example.test")
    assert {source["source"] for source in mail["sources"]} >= {"file", "linux-file"}
    badge = next(item for item in inventory["certificates"] if item["common_name"] == "badge.example.test")
    assert {source["source"] for source in badge["sources"]} >= {"file", "windows-store"}


def test_demo_live_reads_loopback_tls(tmp_path: Path):
    result = run_demo(tmp_path / "live", live=True)
    assert result.elapsed_seconds < 60
    assert result.gaps == 0
    assert result.problem_counts["san_mismatch"] >= 1
    assert result.problem_counts["missing_intermediate"] >= 1
    inventory = json.loads((result.output_dir / "inventory.json").read_text(encoding="utf-8"))
    vpn = next(item for item in inventory["certificates"] if item["common_name"] == "vpn.example.test")
    assert "tls" in {source["source"] for source in vpn["sources"]}


def test_cli_scan_and_checkmk(tmp_path: Path):
    demo = tmp_path / "demo"
    assert main(["demo", "--offline", "--out", str(demo)]) == 0
    config = {
        "database": "scan.db",
        "output_dir": "out",
        "owners_file": None,
        "windows_json": [],
        "linux_json": [str(demo / "inventory.json")],
        "adcs_csv": [],
        "file_paths": [],
        "horizon_days": 90,
        "webhook": {"enabled": False, "url": "", "format": "generic"},
    }
    # inventory.json is a report, not a linux export. Build a real config from the demo db via report.
    config_path = tmp_path / "certpilot.yml"
    owners = tmp_path / "owners.yml"
    owners.write_text(
        yaml.safe_dump({"rules": [{"owner": "mail-team", "service": "mail", "match": {"any": True}}]}),
        encoding="utf-8",
    )
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# no endpoints\n", encoding="utf-8")
    config = {
        "database": "scan.db",
        "output_dir": "scan-out",
        "hosts_file": "hosts.txt",
        "owners_file": "owners.yml",
        "file_paths": [],
        "windows_json": [],
        "linux_json": [],
        "adcs_csv": [],
        "webhook": {"enabled": True, "url": "http://127.0.0.1:9/hook", "format": "generic"},
    }
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    assert main(["scan", "--config", str(config_path)]) == 0
    summary = (tmp_path / "scan-out" / "index.html").read_text(encoding="utf-8")
    assert "Certificate expiry timeline" in summary
    db = tmp_path / "scan.db"
    assert main(["checkmk", "--db", str(db), "--owners", str(owners)]) == 0
    exported = tmp_path / "collectors"
    assert main(["export-collectors", "--dest", str(exported)]) == 0
    assert (exported / "Get-CertPilotStore.ps1").is_file()
    assert (exported / "collect_linux_certs.py").is_file()
    preview = json.loads((tmp_path / "scan-out" / "webhook-preview.json").read_text(encoding="utf-8"))
    assert preview["sent"] is False


def test_cli_notify_requires_send(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    demo = tmp_path / "demo"
    assert main(["demo", "--offline", "--out", str(demo)]) == 0
    db = demo / "certpilot.db"
    assert main(["notify", "--db", str(db), "--preview"]) == 0
    captured = capsys.readouterr()
    assert "webhook_sent: no" in captured.out
    assert main(["notify", "--db", str(db), "--send", "--url", "file:///tmp/nope"]) == 1


def test_linux_collector_script_emits_metadata_only(tmp_path: Path):
    script = Path(__file__).resolve().parents[1] / "src" / "certpilot" / "bundled" / "collect_linux_certs.py"
    from certpilot.mint import mint
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    minted = mint(
        "linux.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=12),
    )
    (tmp_path / "linux.example.test.pem").write_bytes(minted.pem + minted.key_pem)
    (tmp_path / "secret.pem").write_bytes(minted.key_pem)
    completed = subprocess.run(
        [sys.executable, str(script), str(tmp_path), "--host", "web01.example.test"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "BEGIN PRIVATE KEY" not in completed.stdout
    assert "BEGIN EC PRIVATE KEY" not in completed.stdout
    document = json.loads(completed.stdout)
    assert document["host"] == "web01.example.test"
    assert document["collector"] == "certpilot-linux-files"
    assert len(document["certificates"]) == 1
    cert = document["certificates"][0]
    assert cert["subject"] == "CN=linux.example.test"
    assert len(cert["fingerprint_sha256"]) == 64
    assert cert["sans"] == ["linux.example.test"]
    assert any("private key" in warning for warning in document["warnings"])


def test_entry_points_are_registered():
    from importlib.metadata import entry_points

    found = entry_points(group="certpilot.collectors")
    names = {item.name for item in found}
    assert {"tls", "files", "windows", "adcs", "linux"} <= names


@pytest.mark.parametrize("as_string", [False, True])
def test_demo_relative_output_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, as_string: bool
):
    monkeypatch.chdir(tmp_path)
    destination = Path("nested") / "demo"
    output_dir = str(destination) if as_string else destination

    for dirty in (False, True):
        if dirty:
            work = destination / ".work"
            work.mkdir()
            (work / "owners.yml").write_text("invalid: [", encoding="utf-8")
            (work / "stale.key").write_text("stale material", encoding="utf-8")

        result = run_demo(output_dir, live=False)

        assert result.output_dir == destination
        assert all(path.is_file() for path in result.files.values())
        assert not (destination / ".work").exists()
        document = json.loads(
            (destination / "inventory.json").read_text(encoding="utf-8")
        )
        mail = next(
            cert
            for cert in document["certificates"]
            if cert["common_name"] == "mail.example.test"
        )
        assert mail["owner"] == "mail-team"
        assert mail["service"] == "mail"


def _outputs(directory: Path) -> str:
    chunks = []
    for path in directory.rglob("*"):
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)
