"""Turn inventory rows into plain-language findings and dependency notes."""

from __future__ import annotations

import datetime as dt
import ipaddress

from certpilot.dates import bucket_for, days_remaining, format_date, relative_expiry
from certpilot.models import Problem, ReportCert, StoredCert
from certpilot.parse import is_sha1

BUCKET_LABELS = {
    "expired": "Expired",
    "within_7": "Within 7 days",
    "within_30": "Within 30 days",
    "within_90": "Within 90 days",
    "later": "Later than 90 days",
}

SOURCE_LABELS = {
    "tls": "TLS endpoint",
    "tls-chain": "TLS chain",
    "file": "File",
    "windows-store": "Windows certificate store",
    "adcs": "ADCS issued-certificate export",
    "linux-file": "Linux file",
}


def source_label(source: str) -> str:
    return SOURCE_LABELS.get(source, source)


def hostname_matches(requested: str, sans: list[str], common_name: str) -> bool:
    """True when ``requested`` is covered by the SAN, or by the CN if there is no SAN."""

    req = requested.strip().rstrip(".").lower()
    if not req:
        return False
    ip_value: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        ip_value = ipaddress.ip_address(req)
    except ValueError:
        ip_value = None
    if sans:
        for san in sans:
            candidate = san.strip()
            if ip_value is not None:
                try:
                    if ipaddress.ip_address(candidate) == ip_value:
                        return True
                except ValueError:
                    continue
            elif _dns_match(req, candidate.rstrip(".").lower()):
                return True
        return False
    if ip_value is not None:
        return False
    if not common_name:
        return False
    return _dns_match(req, common_name.strip().rstrip(".").lower())


def _dns_match(name: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not name.endswith(suffix):
            return False
        head = name[: -len(suffix)]
        return bool(head) and "." not in head
    return name == pattern


def _expiry_problem(cert: StoredCert, now: dt.datetime) -> Problem | None:
    days = days_remaining(cert.not_after, now)
    when = relative_expiry(cert.not_after, now)
    subject = cert.subject_cn
    if days < 0:
        return Problem(
            "expired",
            f"{subject} {when}. Clients that check dates will reject it.",
        )
    if days <= 7:
        return Problem(
            "expires_within_7",
            f"{subject} {when}, inside the 7-day window.",
        )
    if days <= 30:
        return Problem(
            "expires_within_30",
            f"{subject} {when}, inside the 30-day window.",
        )
    if days <= 90:
        return Problem(
            "expires_within_90",
            f"{subject} {when}, inside the 90-day window.",
        )
    return None


def _weak_key_problem(cert: StoredCert, weak_rsa_bits: int) -> Problem | None:
    if cert.key_type == "DSA":
        return Problem(
            "weak_key",
            "This certificate uses a DSA key. DSA certificates are obsolete and should be replaced.",
        )
    if cert.key_type == "RSA" and cert.key_size is not None and cert.key_size < weak_rsa_bits:
        return Problem(
            "weak_key",
            f"The RSA key is {cert.key_size} bits. Keys shorter than {weak_rsa_bits} bits "
            "are treated as weak because they are practical to factor.",
        )
    if cert.key_type == "EC" and cert.key_size is not None and cert.key_size < 256:
        return Problem(
            "weak_key",
            f"The EC key is {cert.key_size} bits. Curves smaller than 256 bits are treated as weak.",
        )
    return None


def _sha1_problem(cert: StoredCert) -> Problem | None:
    if not is_sha1(cert.signature_algorithm):
        return None
    algorithm = cert.signature_algorithm or "SHA-1"
    return Problem(
        "sha1",
        f"This certificate is signed with SHA-1 ({algorithm}). SHA-1 signatures are no longer "
        "trusted by current browsers and operating systems.",
    )


def _self_signed_problem(cert: StoredCert) -> Problem | None:
    if not cert.self_signed or cert.is_ca is True:
        return None
    if cert.is_ca is False:
        return Problem(
            "self_signed",
            "This end-entity certificate is self-signed (subject and issuer are the same). "
            "Clients trust it only where an administrator has explicitly installed it.",
        )
    return Problem(
        "self_signed",
        "This certificate is self-signed (subject and issuer are the same). If it is not an "
        "installed root, clients will reject it until someone explicitly trusts it.",
    )


def _index(certs: list[StoredCert]) -> tuple[dict[str, list[StoredCert]], dict[str, StoredCert]]:
    by_subject: dict[str, list[StoredCert]] = {}
    by_fingerprint: dict[str, StoredCert] = {}
    for cert in certs:
        by_fingerprint[cert.fingerprint] = cert
        if cert.subject_normalized:
            by_subject.setdefault(cert.subject_normalized, []).append(cert)
    return by_subject, by_fingerprint


def _choose_issuer(leaf: StoredCert, candidates: list[StoredCert]) -> StoredCert | None:
    pool = [item for item in candidates if item.fingerprint != leaf.fingerprint]
    if not pool:
        return None
    if leaf.authority_key_id:
        by_ski = [
            item
            for item in pool
            if item.subject_key_id and item.subject_key_id == leaf.authority_key_id
        ]
        if by_ski:
            pool = by_ski
    covered = [item for item in pool if item.not_before <= leaf.not_before <= item.not_after]
    if covered:
        pool = covered
    return min(pool, key=lambda item: item.not_after)


def _chain_includes_issuer(
    leaf: StoredCert,
    fingerprints: list[str],
    by_fingerprint: dict[str, StoredCert],
) -> bool:
    for fingerprint in fingerprints:
        other = by_fingerprint.get(fingerprint)
        if other is None:
            continue
        if other.subject_normalized == leaf.issuer_normalized:
            return True
        if leaf.authority_key_id and other.subject_key_id == leaf.authority_key_id:
            return True
    return False


def _san_list(cert: StoredCert) -> str:
    if cert.sans:
        return ", ".join(cert.sans)
    if cert.subject_cn:
        return f"no SAN; common name {cert.subject_cn}"
    return "no names"


def explain(
    certs: list[StoredCert],
    now: dt.datetime,
    *,
    weak_rsa_bits: int = 2048,
    owners: dict[str, tuple[str | None, str | None, str | None]] | None = None,
) -> list[ReportCert]:
    """Build report rows. ``owners`` maps fingerprint to (owner, service, note)."""

    by_subject, by_fingerprint = _index(certs)
    rows: list[ReportCert] = []
    owner_map = owners or {}
    for cert in certs:
        problems: list[Problem] = []
        expiry = _expiry_problem(cert, now)
        if expiry is not None:
            problems.append(expiry)

        issuer = None
        dependency = None
        if not cert.self_signed and cert.issuer_normalized:
            issuer = _choose_issuer(cert, by_subject.get(cert.issuer_normalized, []))
        if issuer is not None:
            dependency = (
                f"Depends on {issuer.subject_cn} ({issuer.fingerprint[:12]}), "
                f"which {relative_expiry(issuer.not_after, now)}."
            )
            if issuer.not_after < cert.not_after:
                problems.append(
                    Problem(
                        "issuer_expires_first",
                        f'The issuing certificate "{issuer.subject_cn}" '
                        f"{relative_expiry(issuer.not_after, now)}, which is before this "
                        f"certificate's own expiry on {format_date(cert.not_after)}. "
                        "Clients stop trusting this certificate when the issuer expires, "
                        "even if the leaf date is still in the future.",
                    )
                )

        chain_observations = [obs for obs in cert.observations if obs.chain_seen]
        omitted_details: list[str] = []
        proved_missing = False
        for obs in chain_observations:
            includes = _chain_includes_issuer(cert, obs.chain_fingerprints, by_fingerprint)
            if includes:
                continue
            if issuer is None:
                proved_missing = True
            else:
                omitted_details.append(obs.detail)
        if proved_missing:
            problems.append(
                Problem(
                    "missing_intermediate",
                    f'The TLS chain did not include the issuer "{cert.issuer}", and that issuer '
                    "is not in this inventory. Clients can fail with a missing-intermediate error "
                    "until the CA certificate is served during the handshake or installed locally.",
                )
            )
        elif issuer is None and not cert.self_signed and cert.issuer_normalized:
            problems.append(
                Problem(
                    "issuer_not_in_inventory",
                    f'The issuer "{cert.issuer}" is not in this inventory, so CertPilot cannot '
                    "time that dependency. Collect the issuing CA from a file, the Windows CA "
                    "store, or a TLS chain to see whether it expires first.",
                )
            )
        elif omitted_details and not (issuer.is_ca and issuer.self_signed):
            # Self-signed roots are normally absent from the handshake on purpose.
            where = "; ".join(omitted_details)
            problems.append(
                Problem(
                    "chain_omits_issuer",
                    f'The TLS chain ({where}) did not include "{issuer.subject_cn}", which is in '
                    "this inventory. Clients that do not already have that intermediate installed "
                    "will fail the handshake until the server sends it.",
                )
            )

        for obs in cert.observations:
            if obs.requested_name and obs.name_matches is False:
                problems.append(
                    Problem(
                        "san_mismatch",
                        f'The name requested from {obs.detail} was "{obs.requested_name}", but it '
                        f"is not covered by this certificate ({_san_list(cert)}). Clients that "
                        "verify the hostname will reject the connection.",
                    )
                )

        weak = _weak_key_problem(cert, weak_rsa_bits)
        if weak is not None:
            problems.append(weak)
        sha1 = _sha1_problem(cert)
        if sha1 is not None:
            problems.append(sha1)
        signed = _self_signed_problem(cert)
        if signed is not None:
            problems.append(signed)

        owner, service, note = owner_map.get(cert.fingerprint, (None, None, None))
        rows.append(
            ReportCert(
                fingerprint=cert.fingerprint,
                serial=cert.serial,
                subject=cert.subject,
                subject_cn=cert.subject_cn,
                issuer=cert.issuer,
                not_before=cert.not_before,
                not_after=cert.not_after,
                days_remaining=days_remaining(cert.not_after, now),
                bucket=bucket_for(days_remaining(cert.not_after, now)),
                sans=list(cert.sans),
                key_type=cert.key_type,
                key_size=cert.key_size,
                signature_algorithm=cert.signature_algorithm,
                self_signed=cert.self_signed,
                is_ca=cert.is_ca,
                owner=owner,
                service=service,
                owner_note=note,
                dependency_note=dependency,
                problems=problems,
                sources=list(cert.observations),
            )
        )
    rows.sort(key=lambda item: (item.days_remaining, item.subject_cn.lower(), item.fingerprint))
    return rows
