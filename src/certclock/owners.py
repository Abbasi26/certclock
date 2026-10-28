"""Map certificates to an owner and a service. First matching rule wins."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from certclock.models import StoredCert
from certclock.parse import normalize_serial

_MATCH_KEYS = {
    "any",
    "common_name",
    "common_name_contains",
    "subject_contains",
    "issuer_contains",
    "san_contains",
    "san_suffix",
    "source",
    "source_detail_contains",
    "serial",
}


@dataclass(frozen=True)
class OwnerRule:
    owner: str
    service: str | None
    note: str | None
    match: dict


def load_owners(path: str | Path) -> list[OwnerRule]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: owner file must be a mapping")
    rules = raw.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError(f"{path}: 'rules' must be a list")
    loaded: list[OwnerRule] = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"{path}: rule {index} must be a mapping")
        match = rule.get("match")
        if not isinstance(match, dict) or not match:
            raise ValueError(f"{path}: rule {index} needs a non-empty 'match' mapping")
        unknown = sorted(set(match) - _MATCH_KEYS)
        if unknown:
            raise ValueError(
                f"{path}: rule {index} has unknown match keys: {', '.join(unknown)}"
            )
        if "any" in match and match["any"] is not True:
            raise ValueError(f"{path}: rule {index} 'any' must be true")
        owner = rule.get("owner")
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError(f"{path}: rule {index} needs an owner")
        service = rule.get("service")
        note = rule.get("note")
        loaded.append(
            OwnerRule(
                owner=owner.strip(),
                service=service.strip() if isinstance(service, str) else None,
                note=note.strip() if isinstance(note, str) else None,
                match=match,
            )
        )
    return loaded


def _contains(haystack: str, needle: str) -> bool:
    return needle.lower() in haystack.lower()


def matches(cert: StoredCert, rule: OwnerRule) -> bool:
    match = rule.match
    if match.get("any") is True and len(match) == 1:
        return True
    if "common_name" in match:
        if cert.subject_cn.lower() != str(match["common_name"]).lower():
            return False
    if "common_name_contains" in match:
        if not _contains(cert.subject_cn, str(match["common_name_contains"])):
            return False
    if "subject_contains" in match:
        if not _contains(cert.subject, str(match["subject_contains"])):
            return False
    if "issuer_contains" in match:
        if not _contains(cert.issuer, str(match["issuer_contains"])):
            return False
    if "san_contains" in match:
        needle = str(match["san_contains"]).lower()
        if not any(needle in san.lower() for san in cert.sans):
            return False
    if "san_suffix" in match:
        suffix = str(match["san_suffix"]).lower()
        names = [san.lower() for san in cert.sans] or [cert.subject_cn.lower()]
        if not any(name.endswith(suffix) for name in names):
            return False
    if "source" in match:
        wanted = str(match["source"])
        if not any(obs.source == wanted for obs in cert.observations):
            return False
    if "source_detail_contains" in match:
        needle = str(match["source_detail_contains"]).lower()
        if not any(needle in obs.detail.lower() for obs in cert.observations):
            return False
    if "serial" in match:
        if normalize_serial(str(match["serial"])) != cert.serial_normalized:
            return False
    return True


def assign_owners(
    certs: list[StoredCert], rules: list[OwnerRule]
) -> dict[str, tuple[str | None, str | None, str | None]]:
    assigned: dict[str, tuple[str | None, str | None, str | None]] = {}
    for cert in certs:
        for rule in rules:
            if matches(cert, rule):
                assigned[cert.fingerprint] = (rule.owner, rule.service, rule.note)
                break
    return assigned
