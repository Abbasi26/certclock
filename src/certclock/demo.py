"""Offline demo. Fictional names only, on the reserved example.test domain."""

from __future__ import annotations

import datetime as dt
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption, pkcs12

from certclock.collectors.adcs import AdcsCollector
from certclock.collectors.files import FileCollector
from certclock.collectors.linux_json import LinuxJsonCollector
from certclock.collectors.tls import TlsCollector
from certclock.collectors.windows_store import WindowsStoreCollector
from certclock.config import Config
from certclock.dates import format_datetime, utcnow
from certclock.hosts import Endpoint
from certclock.inventory import Inventory
from certclock.localtls import LocalTlsServer
from certclock.mint import Minted, mint, mint_sha1
from certclock.parse import fingerprint_der, pem_certificates
from certclock.pipeline import build_report
from certclock.outputs import write_reports


@dataclass
class DemoResult:
    output_dir: Path
    elapsed_seconds: float
    live: bool
    summary: dict[str, int]
    problem_counts: dict[str, int]
    warnings: int
    gaps: int
    files: dict[str, Path]


def run_demo(output_dir: str | Path, *, live: bool = True) -> DemoResult:
    """Build a fictional inventory and render every report. Deletes key material."""

    started = time.perf_counter()
    now = utcnow()
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    database = destination / "certclock.db"
    if database.exists():
        database.unlink()
    work = destination / ".work"
    if work.exists():
        _remove_tree(work)
    work.mkdir()
    servers: list[LocalTlsServer] = []
    try:
        material = _material(work, now)
        endpoints: list[Endpoint] = []
        if live:
            servers, endpoints = _serve(material)
        with Inventory(database) as inventory:
            inventory.ingest(FileCollector([material["certs"]]).collect(), now)
            inventory.ingest(WindowsStoreCollector([material["windows"]]).collect(), now)
            inventory.ingest(AdcsCollector([{"path": str(material["adcs"]), "issuer": ""}]).collect(), now)
            inventory.ingest(LinuxJsonCollector([material["linux"]]).collect(), now)
            if endpoints:
                inventory.ingest(TlsCollector(endpoints, timeout=8).collect(), now)
            _relativize_paths(inventory, work)
            config = Config(
                owners_file=str(material["owners"]),
                horizon_days=90,
                warn_days=30,
                crit_days=7,
                notify_within_days=30,
            )
            report = build_report(inventory, config, now)
            files = write_reports(report, destination)
    finally:
        for server in servers:
            server.stop()
        _remove_tree(work)
    files["database"] = database
    elapsed = time.perf_counter() - started
    counts: dict[str, int] = {}
    for cert in report.certificates:
        for problem in cert.problems:
            counts[problem.code] = counts.get(problem.code, 0) + 1
    return DemoResult(
        output_dir=destination,
        elapsed_seconds=elapsed,
        live=live,
        summary=report.summary(),
        problem_counts=counts,
        warnings=len(report.warnings),
        gaps=len(report.gaps),
        files=files,
    )


def format_summary(result: DemoResult) -> str:
    summary = result.summary
    lines = [
        "CertClock 0.2.0 demo",
        f"live_tls: {'yes' if result.live else 'no'}",
        f"certificates: {summary['total']}",
        f"expired: {summary['expired']}",
        f"within_7: {summary['within_7']}",
        f"within_30: {summary['within_30']}",
        f"within_90: {summary['within_90']}",
        f"later: {summary['later']}",
        f"warnings: {result.warnings}",
        f"gaps: {result.gaps}",
    ]
    if result.problem_counts:
        lines.append("problems:")
        for code in sorted(result.problem_counts):
            lines.append(f"  {code}: {result.problem_counts[code]}")
    for label in ("html", "ics", "checkmk", "prometheus", "json", "csv", "webhook_preview"):
        lines.append(f"{label}: {result.files[label]}")
    lines.append("webhook_sent: no")
    lines.append(f"elapsed_seconds: {result.elapsed_seconds:.2f}")
    return "\n".join(lines) + "\n"


def _material(work: Path, now: dt.datetime) -> dict:
    certs = work / "certs"
    certs.mkdir()
    root = mint(
        "Example Laboratory Root CA",
        is_ca=True,
        key="ec",
        path_length=1,
        sans=[],
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=900),
    )
    issuing = mint(
        "Example Laboratory Issuing CA",
        is_ca=True,
        key="rsa",
        path_length=0,
        sans=[],
        issuer=root,
        not_before=now - dt.timedelta(days=20),
        not_after=now + dt.timedelta(days=70),
    )
    other = mint(
        "Example Laboratory Other CA",
        is_ca=True,
        key="ec",
        path_length=0,
        sans=[],
        not_before=now - dt.timedelta(days=10),
        not_after=now + dt.timedelta(days=400),
    )
    made = {
        "intranet.example.test": mint(
            "intranet.example.test",
            issuer=issuing,
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=200),
        ),
        "vpn.example.test": mint(
            "vpn.example.test",
            issuer=issuing,
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=5),
        ),
        "mail.example.test": mint(
            "mail.example.test",
            issuer=issuing,
            not_before=now - dt.timedelta(days=400),
            not_after=now - dt.timedelta(days=12),
        ),
        "legacy.example.test": mint(
            "legacy.example.test",
            issuer=issuing,
            key="rsa1024",
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=20),
        ),
        "printer.example.test": mint(
            "printer.example.test",
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=16),
        ),
        "www.example.test": mint(
            "www.example.test",
            sans=["www.example.test"],
            issuer=issuing,
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=35),
        ),
        "orphan.example.test": mint(
            "orphan.example.test",
            issuer=other,
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=50),
        ),
        "status.example.test": mint(
            "status.example.test",
            issuer=issuing,
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=180),
        ),
        "wiki.example.test": mint(
            "wiki.example.test",
            issuer=issuing,
            not_before=now - dt.timedelta(days=15),
            not_after=now + dt.timedelta(days=60),
        ),
    }
    badge = mint_sha1(issuing, "badge.example.test", days=25)
    _write_public(certs / "root.pem", root)
    _write_public(certs / "issuing.pem", issuing)
    for name, minted in made.items():
        if name in {"wiki.example.test", "mail.example.test"}:
            continue
        _write_public(certs / f"{name}.pem", minted)
    # A combined PEM proves the key is ignored. Only the public certificate is kept.
    (certs / "mail.example.test.pem").write_bytes(made["mail.example.test"].pem + made["mail.example.test"].key_pem)
    wiki = made["wiki.example.test"]
    (certs / "wiki.example.test.pfx").write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"wiki.example.test",
            key=wiki.key,
            cert=wiki.certificate,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )
    )
    locked = mint(
        "locked.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=10),
    )
    (certs / "locked.example.test.pfx").write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"locked.example.test",
            key=locked.key,
            cert=locked.certificate,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(os.urandom(8).hex().encode("ascii")),
        )
    )
    _write_public(certs / "badge.example.test.pem", badge)
    windows = work / "windows.json"
    linux = work / "linux.json"
    adcs = work / "adcs.csv"
    owners = work / "owners.yml"
    windows.write_text(_windows_json(badge, now), encoding="utf-8")
    linux.write_text(_linux_json(made["mail.example.test"], now), encoding="utf-8")
    adcs.write_text(_adcs_csv(issuing, now), encoding="utf-8")
    owners.write_text(_OWNERS, encoding="utf-8")
    return {
        "certs": certs,
        "windows": windows,
        "linux": linux,
        "adcs": adcs,
        "owners": owners,
        "issuing": issuing,
        "leaves": made,
        "badge": badge,
    }


def _serve(material: dict) -> tuple[list[LocalTlsServer], list[Endpoint]]:
    leaves: dict[str, Minted] = material["leaves"]
    issuing: Minted = material["issuing"]
    specs = [
        ("intranet.example.test", leaves["intranet.example.test"], issuing.pem),
        ("vpn.example.test", leaves["vpn.example.test"], issuing.pem),
        ("shop.example.test", leaves["www.example.test"], b""),
        ("orphan.example.test", leaves["orphan.example.test"], b""),
    ]
    servers: list[LocalTlsServer] = []
    endpoints: list[Endpoint] = []
    try:
        for sni, minted, extra in specs:
            if minted.key_pem is None:
                raise RuntimeError(f"no key for {sni}")
            server = LocalTlsServer(minted.pem, minted.key_pem, extra).start()
            servers.append(server)
            endpoints.append(Endpoint("127.0.0.1", server.port, sni, f"127.0.0.1:{server.port} {sni}"))
    except Exception:
        for server in servers:
            server.stop()
        raise
    return servers, endpoints


def _write_public(path: Path, minted: Minted) -> None:
    path.write_bytes(minted.pem)


def _fingerprint(minted: Minted) -> str:
    ders = pem_certificates(minted.pem)
    return fingerprint_der(ders[0] if ders else minted.der)


def _windows_json(badge: Minted, now: dt.datetime) -> str:
    cert = badge.certificate
    document = {
        "collector": "certclock-windows-store",
        "version": 1,
        "host": "FILE-01",
        "collected_at": format_datetime(now),
        "certificates": [
            {
                "store_location": "LocalMachine",
                "store_name": "My",
                "thumbprint_sha256": _fingerprint(badge),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "x"),
                "not_before": format_datetime(cert.not_valid_before_utc),
                "not_after": format_datetime(cert.not_valid_after_utc),
                "sans": ["badge.example.test"],
                "key_type": "RSA",
                "key_size": 2048,
                "signature_algorithm": "sha1WithRSAEncryption",
                "has_private_key": False,
                "is_ca": False,
            }
        ],
    }
    return json.dumps(document, indent=2)


def _linux_json(mail: Minted, now: dt.datetime) -> str:
    cert = mail.certificate
    document = {
        "collector": "certclock-linux-files",
        "version": 1,
        "host": "web01.example.test",
        "collected_at": format_datetime(now),
        "warnings": [],
        "certificates": [
            {
                "path": "/etc/ssl/certs/mail.example.test.pem",
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "x"),
                "not_before": format_datetime(cert.not_valid_before_utc),
                "not_after": format_datetime(cert.not_valid_after_utc),
                "sans": ["mail.example.test"],
                "fingerprint_sha256": _fingerprint(mail),
                "key_type": "EC",
                "key_size": 256,
                "signature_algorithm": "sha256WithRSAEncryption",
                "is_ca": False,
            }
        ],
    }
    return json.dumps(document, indent=2)


def _adcs_csv(issuing: Minted, now: dt.datetime) -> str:
    issuer = issuing.certificate.subject.rfc4514_string()
    not_before = (now - dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = (now + dt.timedelta(days=11)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        "Request ID,Requester Name,Request Common Name,Request Disposition,"
        "Certificate Template,Serial Number,Certificate Effective Date,"
        "Certificate Expiration Date,Issuer Name\n"
        f'"1042","EXAMPLE\\svc-enroll","laptop-enroll.example.test","20",'
        f'"User","a1b2c3d4","{not_before}","{not_after}","{issuer}"\n'
        '"1043","EXAMPLE\\svc-enroll","revoked.example.test","21","User",'
        f'"ff00","{not_before}","{not_after}","{issuer}"\n'
        "CertUtil: -view command completed successfully.\n"
    )


def _relativize_paths(inventory: Inventory, work: Path) -> None:
    """Drop the temporary directory from the report before that directory is deleted."""

    prefix = str(work) + "/"
    warnings = inventory.conn.execute("SELECT id, message FROM warnings").fetchall()
    for row in warnings:
        inventory.conn.execute(
            "UPDATE warnings SET message = ? WHERE id = ?",
            (row["message"].replace(prefix, ""), row["id"]),
        )
    observations = inventory.conn.execute(
        "SELECT fingerprint, source, detail FROM observations"
    ).fetchall()
    for row in observations:
        if not str(row["detail"]).startswith(prefix):
            continue
        inventory.conn.execute(
            """
            UPDATE observations SET detail = ?
            WHERE fingerprint = ? AND source = ? AND detail = ?
            """,
            (
                row["detail"][len(prefix) :],
                row["fingerprint"],
                row["source"],
                row["detail"],
            ),
        )
    inventory.conn.commit()
    inventory.conn.execute("VACUUM")


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file() or child.is_symlink():
            child.unlink()
        else:
            child.rmdir()
    path.rmdir()


_OWNERS = yaml.safe_dump(
    {
        "rules": [
            {"owner": "network-team", "service": "remote-access", "note": "Remote access gateway", "match": {"common_name": "vpn.example.test"}},
            {"owner": "mail-team", "service": "mail", "match": {"common_name": "mail.example.test"}},
            {"owner": "platform", "service": "intranet", "note": "Depends on the issuing CA", "match": {"common_name": "intranet.example.test"}},
            {"owner": "platform", "service": "status", "match": {"common_name": "status.example.test"}},
            {"owner": "commerce", "service": "storefront", "match": {"common_name": "www.example.test"}},
            {"owner": "facilities", "service": "printer", "match": {"common_name": "printer.example.test"}},
            {"owner": "endpoint-team", "service": "client-auth", "match": {"common_name": "laptop-enroll.example.test"}},
            {"owner": "knowledge", "service": "wiki", "match": {"common_name": "wiki.example.test"}},
            {"owner": "identity", "service": "badge", "match": {"common_name": "badge.example.test"}},
            {"owner": "platform", "service": "legacy-vpn", "match": {"common_name": "legacy.example.test"}},
            {"owner": "pki", "service": "issuing-ca", "match": {"common_name": "Example Laboratory Issuing CA"}},
            {"owner": "pki", "service": "root-ca", "match": {"common_name": "Example Laboratory Root CA"}},
            {"owner": "platform", "service": "orphan-app", "match": {"common_name": "orphan.example.test"}},
        ]
    },
    sort_keys=False,
)
