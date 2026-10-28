"""Plain-language findings, buckets, owners, and dependencies."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from certclock.dates import bucket_for, days_remaining
from certclock.explain import explain, hostname_matches
from certclock.inventory import Inventory
from certclock.mint import mint, mint_sha1
from certclock.models import CollectionResult, Observation, StoredCert, StoredObs
from certclock.owners import OwnerRule, assign_owners, load_owners


def test_bucket_boundaries(now: dt.datetime):
    assert days_remaining(now + dt.timedelta(days=7), now) == 7
    assert bucket_for(7) == "within_7"
    assert bucket_for(8) == "within_30"
    assert bucket_for(30) == "within_30"
    assert bucket_for(31) == "within_90"
    assert bucket_for(90) == "within_90"
    assert bucket_for(91) == "later"
    assert bucket_for(-1) == "expired"
    assert days_remaining(now - dt.timedelta(seconds=1), now) == -1
    assert days_remaining(now + dt.timedelta(days=7, seconds=1), now) == 7


def test_hostname_matching():
    assert hostname_matches("vpn.example.test", ["vpn.example.test"], "vpn.example.test")
    assert hostname_matches("a.example.test", ["*.example.test"], "example.test")
    assert not hostname_matches("a.b.example.test", ["*.example.test"], "example.test")
    assert not hostname_matches("shop.example.test", ["www.example.test"], "www.example.test")
    assert hostname_matches("legacy.example.test", [], "legacy.example.test")


def test_weak_sha1_self_signed_and_issuer_order(tmp_path, now: dt.datetime):
    root = mint(
        "Example Laboratory Root CA",
        is_ca=True,
        key="ec",
        path_length=1,
        sans=[],
        not_before=now - dt.timedelta(days=10),
        not_after=now + dt.timedelta(days=400),
    )
    issuing = mint(
        "Example Laboratory Issuing CA",
        is_ca=True,
        key="rsa",
        path_length=0,
        sans=[],
        issuer=root,
        not_before=now - dt.timedelta(days=5),
        not_after=now + dt.timedelta(days=50),
    )
    leaf = mint(
        "intranet.example.test",
        issuer=issuing,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=200),
    )
    weak = mint(
        "legacy.example.test",
        issuer=issuing,
        key="rsa1024",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=10),
    )
    printer = mint(
        "printer.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=10),
    )
    badge = mint_sha1(issuing, "badge.example.test", days=30)
    with Inventory(tmp_path / "findings.db") as inventory:
        observations = []
        for detail, minted in (
            ("root.pem", root),
            ("issuing.pem", issuing),
            ("intranet.pem", leaf),
            ("legacy.pem", weak),
            ("printer.pem", printer),
            ("badge.pem", badge),
        ):
            observations.append(Observation(source="file", detail=detail, der=minted.der))
        inventory.ingest(
            CollectionResult(observations=observations, replaced_sources=("file",)),
            now,
        )
        rows = {row.subject_cn: row for row in explain(inventory.certificates(), now)}
    intranet = rows["intranet.example.test"]
    assert any(problem.code == "issuer_expires_first" for problem in intranet.problems)
    assert "Issuing CA" in intranet.dependency_note
    assert "practical to factor" in _message(rows["legacy.example.test"], "weak_key")
    assert "SHA-1" in _message(rows["badge.example.test"], "sha1")
    assert "self-signed" in _message(rows["printer.example.test"], "self_signed").lower()
    assert all(problem.code != "self_signed" for problem in rows["Example Laboratory Root CA"].problems)


def test_expiry_messages_are_sentences(tmp_path, now: dt.datetime):
    expired = mint(
        "old.example.test",
        not_before=now - dt.timedelta(days=40),
        not_after=now - dt.timedelta(days=3),
    )
    soon = mint(
        "soon.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=2),
    )
    with Inventory(tmp_path / "expiry.db") as inventory:
        inventory.ingest(
            CollectionResult(
                observations=[
                    Observation(source="file", detail="old.pem", der=expired.der),
                    Observation(source="file", detail="soon.pem", der=soon.der),
                ],
                replaced_sources=("file",),
            ),
            now,
        )
        rows = {row.subject_cn: row for row in explain(inventory.certificates(), now)}
    assert rows["old.example.test"].bucket == "expired"
    assert "expired" in _message(rows["old.example.test"], "expired").lower()
    assert "7-day" in _message(rows["soon.example.test"], "expires_within_7")


def test_owners_first_match_wins(tmp_path, now: dt.datetime):
    minted = mint(
        "vpn.example.test",
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=12),
    )
    rules_path = tmp_path / "owners.yml"
    rules_path.write_text(
        """
        rules:
          - owner: network-team
            service: remote-access
            note: Remote access gateway
            match:
              common_name: vpn.example.test
          - owner: everyone
            service: catch-all
            match:
              san_suffix: ".example.test"
          - owner: bad
            match:
              nope: true
        """,
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown match keys"):
        load_owners(rules_path)
    rules_path.write_text(
        """
        rules:
          - owner: network-team
            service: remote-access
            note: Remote access gateway
            match:
              common_name: vpn.example.test
          - owner: everyone
            service: catch-all
            match:
              any: true
        """,
        encoding="utf-8",
    )
    rules = load_owners(rules_path)
    with Inventory(tmp_path / "owners.db") as inventory:
        inventory.ingest(
            CollectionResult(
                observations=[
                    Observation(source="file", detail="vpn.pem", der=minted.der),
                    Observation(
                        source="file",
                        detail="other.pem",
                        der=mint(
                            "other.example.test",
                            not_before=now,
                            not_after=now + dt.timedelta(days=10),
                        ).der,
                    ),
                ],
                replaced_sources=("file",),
            ),
            now,
        )
        stored = inventory.certificates()
    assigned = assign_owners(stored, rules)
    by_cn = {cert.subject_cn: assigned[cert.fingerprint] for cert in stored}
    assert by_cn["vpn.example.test"][0] == "network-team"
    assert by_cn["vpn.example.test"][2] == "Remote access gateway"
    assert by_cn["other.example.test"][0] == "everyone"


def test_manual_owner_rule_requires_every_key(now: dt.datetime):
    cert = StoredCert(
        fingerprint="abc",
        kind="meta",
        serial="1",
        serial_normalized="1",
        subject="CN=vpn.example.test",
        subject_cn="vpn.example.test",
        subject_normalized="cn=vpn.example.test",
        issuer="CN=ca",
        issuer_normalized="cn=ca",
        not_before=now,
        not_after=now + dt.timedelta(days=1),
        sans=["vpn.example.test"],
        key_type="EC",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        self_signed=False,
        is_ca=False,
        subject_key_id=None,
        authority_key_id=None,
        observations=[
            StoredObs("file", "/etc/ssl/vpn.pem", now, None, None, False, [])
        ],
    )
    rule = OwnerRule(
        "linux-ops",
        "host-tls",
        None,
        {"source": "file", "source_detail_contains": "/etc/ssl"},
    )
    assert assign_owners([cert], [rule])["abc"][0] == "linux-ops"


def _message(row, code: str) -> str:
    return next(problem.message for problem in row.problems if problem.code == code)


@pytest.mark.parametrize(
    "value",
    ["false", "null", "0", "1", "'true'", "'false'", "[]", "{}"],
)
def test_owner_any_requires_boolean_true(tmp_path: Path, value: str):
    path = tmp_path / "owners.yml"
    path.write_text(
        f"rules:\n  - owner: fallback\n    match:\n      any: {value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as error:
        load_owners(path)

    assert str(error.value) == f"{path}: rule 1 'any' must be true"

    for condition in ("", "      common_name: mail.example.test\n"):
        path.write_text(
            "rules:\n  - owner: fallback\n    match:\n      any: true\n"
            + condition,
            encoding="utf-8",
        )
        rules = load_owners(path)
        assert len(rules) == 1
        assert rules[0].match["any"] is True


@pytest.mark.parametrize(
    ("document", "valid"),
    [
        ("false\n", False),
        ("0\n", False),
        ("''\n", False),
        ("[]\n", False),
        ("", True),
        ("# no ownership rules\n", True),
        ("null\n", True),
        ("{}\n", True),
        ("rules: []\n", True),
    ],
)
def test_owner_document_requires_mapping(
    tmp_path: Path, document: str, valid: bool
):
    path = tmp_path / "owners.yml"
    path.write_text(document, encoding="utf-8")

    if valid:
        assert load_owners(path) == []
    else:
        with pytest.raises(ValueError) as error:
            load_owners(path)
        assert str(error.value) == f"{path}: owner file must be a mapping"
