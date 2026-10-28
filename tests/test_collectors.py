"""Collectors record public certificates and refuse private keys."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption, pkcs12

from certclock.collectors.adcs import AdcsCollector
from certclock.collectors.files import FileCollector
from certclock.collectors.linux_json import LinuxJsonCollector
from certclock.collectors.tls import TlsCollector
from certclock.collectors.windows_store import WindowsStoreCollector
from certclock.hosts import parse_hosts
from certclock.inventory import Inventory
from certclock.localtls import LocalTlsServer
from certclock.mint import mint
from certclock.models import CollectionResult, Observation
from certclock.parse import fingerprint_der, pem_certificates


def test_hosts_parser_ignores_comments_and_reads_sni():
    endpoints = parse_hosts(
        """
        # comment
        vpn.example.test:443
        10.0.0.8:8443 app.example.test

        [::1]:443 localhost
        """
    )
    assert [(item.host, item.port, item.sni) for item in endpoints] == [
        ("vpn.example.test", 443, "vpn.example.test"),
        ("10.0.0.8", 8443, "app.example.test"),
        ("::1", 443, "localhost"),
    ]


@pytest.mark.parametrize(
    "endpoint",
    [
        "vpn.example.test:443",
        "10.0.0.8:8443",
        "[::1]:443",
    ],
)
def test_hosts_parser_rejects_extra_fields(endpoint: str):
    with pytest.raises(
        ValueError,
        match=r"^hosts line 2: expected endpoint and optional SNI$",
    ):
        parse_hosts(f"# heading\n{endpoint} app.example.test unexpected\n")

    parsed = parse_hosts(
        f"{endpoint} app.example.test # trailing comment words\n"
    )
    assert len(parsed) == 1
    assert parsed[0].sni == "app.example.test"


def test_files_ignore_private_keys_and_skip_encrypted_pfx(tmp_path: Path, now: dt.datetime):
    minted = mint(
        "files.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=12),
    )
    combined = tmp_path / "combined.pem"
    combined.write_bytes(minted.pem + minted.key_pem)
    (tmp_path / "alone.der").write_bytes(minted.der)
    (tmp_path / "open.pfx").write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"files.example.test",
            key=minted.key,
            cert=minted.certificate,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )
    )
    (tmp_path / "locked.pfx").write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"locked",
            key=minted.key,
            cert=minted.certificate,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(b"not-the-password"),
        )
    )
    (tmp_path / "only-key.pem").write_bytes(minted.key_pem)
    result = FileCollector([tmp_path]).collect()
    assert any("password-protected" in warning for warning in result.warnings)
    assert any("ignored private key" in warning for warning in result.warnings)
    assert any("no certificate" in warning for warning in result.warnings)
    with Inventory(tmp_path / "inv.db") as inventory:
        inventory.ingest(result, now)
        certs = inventory.certificates()
        blob = Path(inventory.path).read_bytes()
    assert len(certs) == 1
    assert certs[0].subject_cn == "files.example.test"
    assert len(certs[0].observations) == 3
    assert b"BEGIN PRIVATE KEY" not in blob
    assert b"BEGIN EC PRIVATE KEY" not in blob


def test_tls_chain_san_and_missing_intermediate(now: dt.datetime, tmp_path: Path):
    issuer = mint(
        "Example Laboratory Issuing CA",
        is_ca=True,
        key="ec",
        sans=[],
        not_before=now - dt.timedelta(days=5),
        not_after=now + dt.timedelta(days=70),
    )
    good = mint(
        "vpn.example.test",
        issuer=issuer,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=9),
    )
    other = mint(
        "Example Laboratory Other CA",
        is_ca=True,
        key="ec",
        sans=[],
        not_before=now - dt.timedelta(days=5),
        not_after=now + dt.timedelta(days=70),
    )
    orphan = mint(
        "orphan.example.test",
        issuer=other,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=20),
    )
    shop = mint(
        "www.example.test",
        sans=["www.example.test"],
        issuer=issuer,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=15),
    )
    with LocalTlsServer(good.pem, good.key_pem, issuer.pem) as chained, LocalTlsServer(
        orphan.pem, orphan.key_pem
    ) as alone, LocalTlsServer(shop.pem, shop.key_pem) as mismatch:
        endpoints = parse_hosts(
            "\n".join(
                [
                    f"127.0.0.1:{chained.port} vpn.example.test",
                    f"127.0.0.1:{alone.port} orphan.example.test",
                    f"127.0.0.1:{mismatch.port} shop.example.test",
                ]
            )
        )
        result = TlsCollector(endpoints, timeout=8).collect()
    assert not result.gaps
    with Inventory(tmp_path / "tls.db") as inventory:
        inventory.ingest(result, now)
        # The issuing CA file is what makes a chain omission different from a missing CA.
        inventory.ingest(
            CollectionResult(
                observations=[Observation(source="file", detail="issuing.pem", der=issuer.der)],
                replaced_sources=("file",),
            ),
            now,
        )
        from certclock.explain import explain

        rows = {row.subject_cn: row for row in explain(inventory.certificates(), now)}
    vpn = rows["vpn.example.test"]
    assert vpn.days_remaining == 9
    assert all(problem.code != "san_mismatch" for problem in vpn.problems)
    assert any(obs.source == "tls-chain" for obs in rows["Example Laboratory Issuing CA"].sources)
    orphan_row = rows["orphan.example.test"]
    assert any(problem.code == "missing_intermediate" for problem in orphan_row.problems)
    shop_row = rows["www.example.test"]
    assert any(problem.code == "san_mismatch" for problem in shop_row.problems)
    assert "shop.example.test" in shop_row.problems[-1].message or any(
        "shop.example.test" in problem.message for problem in shop_row.problems
    )


def test_adcs_csv_skips_revoked_and_links_issuer(tmp_path: Path, now: dt.datetime):
    issuer = mint(
        "Example Laboratory Issuing CA",
        is_ca=True,
        key="ec",
        sans=[],
        not_before=now - dt.timedelta(days=30),
        not_after=now + dt.timedelta(days=10),
    )
    issuer_dn = issuer.certificate.subject.rfc4514_string()
    csv_path = tmp_path / "issued.csv"
    csv_path.write_text(
        "\n".join(
            [
                "CertUtil: -view command started",
                "Request ID,Request Common Name,Request Disposition,Serial Number,"
                "Certificate Effective Date,Certificate Expiration Date,Issuer Name",
        f'140,laptop.example.test,20,abc123,{_iso(now)},{_iso(now + dt.timedelta(days=30))},{issuer_dn}',
        f'141,revoked.example.test,21,def456,{_iso(now)},{_iso(now + dt.timedelta(days=30))},{issuer_dn}',
                "CertUtil: -view command completed successfully.",
            ]
        ),
        encoding="utf-8",
    )
    result = AdcsCollector([{"path": str(csv_path)}]).collect()
    assert any("skipped 1" in warning for warning in result.warnings)
    with Inventory(tmp_path / "adcs.db") as inventory:
        inventory.ingest(
            CollectionResult(
                observations=[Observation(source="file", detail="ca.pem", der=issuer.der)],
                replaced_sources=("file",),
            ),
            now,
        )
        inventory.ingest(result, now)
        from certclock.explain import explain

        rows = explain(inventory.certificates(), now)
    names = {row.subject_cn for row in rows}
    assert "laptop.example.test" in names
    assert "revoked.example.test" not in names
    laptop = next(row for row in rows if row.subject_cn == "laptop.example.test")
    assert laptop.dependency_note
    assert "Example Laboratory Issuing CA" in laptop.dependency_note
    assert any(problem.code == "issuer_expires_first" for problem in laptop.problems)


def test_windows_and_linux_dedupe_with_the_file(tmp_path: Path, now: dt.datetime):
    minted = mint(
        "shared.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=18),
    )
    pem = tmp_path / "shared.pem"
    pem.write_bytes(minted.pem)
    fingerprint = fingerprint_der(pem_certificates(minted.pem)[0])
    windows = tmp_path / "windows.json"
    windows.write_text(
        json.dumps(
            {
                "collector": "certclock-windows-store",
                "host": "FILE-01",
                "certificates": {
                    "store_location": "LocalMachine",
                    "store_name": "My",
                    "thumbprint_sha256": fingerprint,
                    "subject": minted.certificate.subject.rfc4514_string(),
                    "issuer": minted.certificate.issuer.rfc4514_string(),
                    "serial": format(minted.certificate.serial_number, "x"),
                    "not_before": _iso(now - dt.timedelta(days=1)),
                    "not_after": _iso(now + dt.timedelta(days=18)),
                    "sans": ["shared.example.test"],
                    "key_type": "EC",
                    "key_size": 256,
                    "signature_algorithm": "ecdsa-with-SHA256",
                    "has_private_key": True,
                },
            }
        ),
        encoding="utf-8",
    )
    linux = tmp_path / "linux.json"
    linux.write_text(
        json.dumps(
            {
                "host": "web01.example.test",
                "certificates": [
                    {
                        "path": "/etc/ssl/certs/shared.pem",
                        "fingerprint_sha256": fingerprint,
                        "subject": minted.certificate.subject.rfc4514_string(),
                        "issuer": minted.certificate.issuer.rfc4514_string(),
                        "serial": format(minted.certificate.serial_number, "x"),
                        "not_before": _iso(now - dt.timedelta(days=1)),
                        "not_after": _iso(now + dt.timedelta(days=18)),
                        "sans": ["shared.example.test"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    refused = tmp_path / "leaky.json"
    refused.write_text('{"certificates": [], "secret": "-----BEGIN PRIVATE KEY-----\\nabc\\n"}', encoding="utf-8")
    with Inventory(tmp_path / "dedupe.db") as inventory:
        inventory.ingest(FileCollector([pem]).collect(), now)
        inventory.ingest(WindowsStoreCollector([windows, refused]).collect(), now)
        inventory.ingest(LinuxJsonCollector([linux]).collect(), now)
        certs = inventory.certificates()
        warnings = inventory.warnings()
    assert len(certs) == 1
    sources = {obs.source for obs in certs[0].observations}
    assert sources == {"file", "windows-store", "linux-file"}
    assert any("refused" in warning for warning in warnings)


def test_custom_collector_is_ingested(tmp_path: Path, now: dt.datetime):
    minted = mint(
        "plugin.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=3),
    )

    class Plugin:
        name = "plugin"
        replaced_sources = ("plugin",)

        def collect(self) -> CollectionResult:
            return CollectionResult(
                observations=[
                    Observation(source="plugin", detail="unit test", der=minted.der)
                ],
                replaced_sources=("plugin",),
            )

    with Inventory(tmp_path / "plugin.db") as inventory:
        inventory.ingest(Plugin().collect(), now)
        certs = inventory.certificates()
    assert certs[0].subject_cn == "plugin.example.test"
    assert certs[0].observations[0].source == "plugin"


def test_metadata_serial_merges_into_der(tmp_path: Path, now: dt.datetime):
    minted = mint(
        "serial.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=6),
    )
    serial = format(minted.certificate.serial_number, "x")
    issuer = minted.certificate.issuer.rfc4514_string()
    meta_first = CollectionResult(
        observations=[
            Observation(
                source="adcs",
                detail="request 9",
                meta={
                    "subject": minted.certificate.subject.rfc4514_string(),
                    "issuer": issuer,
                    "serial": serial,
                    "not_before": _iso(now - dt.timedelta(days=1)),
                    "not_after": _iso(now + dt.timedelta(days=6)),
                    "sans": ["serial.example.test"],
                },
            )
        ],
        replaced_sources=("adcs",),
    )
    with Inventory(tmp_path / "merge.db") as inventory:
        inventory.ingest(meta_first, now)
        inventory.ingest(
            CollectionResult(
                observations=[Observation(source="file", detail="serial.pem", der=minted.der)],
                replaced_sources=("file",),
            ),
            now,
        )
        certs = inventory.certificates()
    assert len(certs) == 1
    assert certs[0].kind == "der"
    assert {obs.source for obs in certs[0].observations} == {"adcs", "file"}


def _iso(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
