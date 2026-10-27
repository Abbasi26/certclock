"""Run collectors, explain the inventory, and write reports."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from certpilot.config import Config
from certpilot.dates import utcnow
from certpilot.explain import explain
from certpilot.hosts import load_hosts
from certpilot.inventory import Inventory
from certpilot.models import Report
from certpilot.outputs import write_reports
from certpilot.outputs.webhook import payload_for, send_webhook
from certpilot.owners import assign_owners, load_owners


@dataclass
class ScanResult:
    report: Report
    files: dict[str, Path]
    webhook_sent: bool
    database: Path


def scan(config: Config, *, send: bool = False, now: dt.datetime | None = None) -> ScanResult:
    """Replace the database with one read-only collection, then write reports.

    ``send`` is the only switch that contacts a webhook. The preview file is
    written either way and is not transmitted on its own.
    """

    moment = now or utcnow()
    database = Path(config.resolve(config.database) or config.database)
    output_dir = Path(config.resolve(config.output_dir) or config.output_dir)
    with Inventory(database) as inventory:
        inventory.wipe()
        for warning in config.warnings:
            inventory.add_warning("config", warning)
            inventory.conn.commit()
        for collector in collectors_from_config(config):
            inventory.ingest(collector.collect(), moment)
        report = build_report(inventory, config, moment)
        files = write_reports(report, output_dir)
        sent = False
        if send:
            sent = _send(config, report)
    return ScanResult(report=report, files=files, webhook_sent=sent, database=database)


def build_report(inventory: Inventory, config: Config, now: dt.datetime) -> Report:
    rules = []
    owners_file = config.resolve(config.owners_file)
    if owners_file:
        rules = load_owners(owners_file)
    stored = inventory.certificates()
    rows = explain(
        stored,
        now,
        weak_rsa_bits=config.weak_rsa_bits,
        owners=assign_owners(stored, rules),
    )
    return Report(
        generated_at=now,
        certificates=rows,
        gaps=inventory.gaps(),
        warnings=inventory.warnings(),
        horizon_days=config.horizon_days,
        warn_days=config.warn_days,
        crit_days=config.crit_days,
        notify_within_days=config.notify_within_days,
    )


def collectors_from_config(config: Config) -> list:
    from certpilot.collectors.adcs import AdcsCollector
    from certpilot.collectors.files import FileCollector
    from certpilot.collectors.linux_json import LinuxJsonCollector
    from certpilot.collectors.tls import TlsCollector
    from certpilot.collectors.windows_store import WindowsStoreCollector

    collectors = []
    if config.hosts_file:
        hosts_path = config.resolve(config.hosts_file)
        collectors.append(
            TlsCollector(load_hosts(hosts_path or ""), timeout=config.tls_timeout_seconds)
        )
    if config.file_paths:
        collectors.append(FileCollector([config.resolve(path) or path for path in config.file_paths]))
    if config.windows_json:
        collectors.append(
            WindowsStoreCollector([config.resolve(path) or path for path in config.windows_json])
        )
    if config.adcs_csv:
        collectors.append(
            AdcsCollector(
                [
                    {"path": config.resolve(item.path) or item.path, "issuer": item.issuer}
                    for item in config.adcs_csv
                ]
            )
        )
    if config.linux_json:
        collectors.append(
            LinuxJsonCollector([config.resolve(path) or path for path in config.linux_json])
        )
    return collectors


def _send(config: Config, report: Report) -> bool:
    if not config.webhook_enabled or not config.webhook_url:
        raise RuntimeError(
            "webhook is off. Set webhook.enabled and webhook.url, or pass --url. "
            "Nothing was sent."
        )
    send_webhook(config.webhook_url, payload_for(report, config.webhook_format))
    return True
