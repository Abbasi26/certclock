"""JSON and CSV snapshots of the report."""

from __future__ import annotations

import csv
import io
import json

from certpilot import __version__
from certpilot.dates import format_datetime
from certpilot.explain import source_label
from certpilot.models import Report


def report_document(report: Report) -> dict:
    counts = report.summary()
    return {
        "tool": "certpilot",
        "version": __version__,
        "generated_at": format_datetime(report.generated_at),
        "summary": counts,
        "warnings": list(report.warnings),
        "gaps": [
            {"source": gap.source, "detail": gap.detail, "message": gap.message}
            for gap in report.gaps
        ],
        "certificates": [_certificate(report, cert) for cert in report.certificates],
    }


def render_json(report: Report) -> str:
    return json.dumps(report_document(report), indent=2, sort_keys=False) + "\n"


def render_csv(report: Report) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "fingerprint",
            "common_name",
            "subject",
            "issuer",
            "serial",
            "not_before",
            "not_after",
            "days_remaining",
            "bucket",
            "owner",
            "service",
            "key_type",
            "key_size",
            "signature_algorithm",
            "sans",
            "sources",
            "problems",
            "dependency_note",
        ]
    )
    for cert in report.certificates:
        writer.writerow(
            [
                cert.fingerprint,
                cert.subject_cn,
                cert.subject,
                cert.issuer,
                cert.serial,
                format_datetime(cert.not_before),
                format_datetime(cert.not_after),
                cert.days_remaining,
                cert.bucket,
                cert.owner or "",
                cert.service or "",
                cert.key_type or "",
                "" if cert.key_size is None else cert.key_size,
                cert.signature_algorithm or "",
                " ".join(cert.sans),
                "; ".join(f"{source_label(obs.source)}: {obs.detail}" for obs in cert.sources),
                " | ".join(problem.message for problem in cert.problems),
                cert.dependency_note or "",
            ]
        )
    return buffer.getvalue()


def _certificate(report: Report, cert) -> dict:
    return {
        "fingerprint": cert.fingerprint,
        "common_name": cert.subject_cn,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "serial": cert.serial,
        "not_before": format_datetime(cert.not_before),
        "not_after": format_datetime(cert.not_after),
        "days_remaining": cert.days_remaining,
        "bucket": cert.bucket,
        "sans": cert.sans,
        "key_type": cert.key_type,
        "key_size": cert.key_size,
        "signature_algorithm": cert.signature_algorithm,
        "self_signed": cert.self_signed,
        "is_ca": cert.is_ca,
        "owner": cert.owner,
        "service": cert.service,
        "owner_note": cert.owner_note,
        "dependency_note": cert.dependency_note,
        "problems": [{"code": problem.code, "message": problem.message} for problem in cert.problems],
        "sources": [
            {
                "source": obs.source,
                "label": source_label(obs.source),
                "detail": obs.detail,
                "collected_at": format_datetime(obs.collected_at),
            }
            for obs in cert.sources
        ],
    }
