"""Load a scan configuration. Unknown keys are reported, not ignored silently."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_KNOWN = {
    "database",
    "output_dir",
    "hosts_file",
    "file_paths",
    "owners_file",
    "windows_json",
    "adcs_csv",
    "linux_json",
    "tls_timeout_seconds",
    "horizon_days",
    "warn_days",
    "crit_days",
    "weak_rsa_bits",
    "notify_within_days",
    "webhook",
}


@dataclass
class AdcsSource:
    path: str
    issuer: str = ""


@dataclass
class Config:
    database: str = "certpilot.db"
    output_dir: str = "certpilot-out"
    hosts_file: str | None = None
    file_paths: list[str] = field(default_factory=list)
    owners_file: str | None = None
    windows_json: list[str] = field(default_factory=list)
    adcs_csv: list[AdcsSource] = field(default_factory=list)
    linux_json: list[str] = field(default_factory=list)
    tls_timeout_seconds: float = 8.0
    horizon_days: int = 90
    warn_days: int = 30
    crit_days: int = 7
    weak_rsa_bits: int = 2048
    notify_within_days: int = 30
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_format: str = "generic"
    warnings: list[str] = field(default_factory=list)

    @property
    def base_dir(self) -> Path | None:
        return getattr(self, "_base_dir", None)

    def resolve(self, value: str | None) -> str | None:
        if value is None or not value:
            return value
        path = Path(value)
        base = self.base_dir
        if base is not None and not path.is_absolute():
            return str((base / path).resolve())
        return str(path)


def load_config(path: str | Path) -> Config:
    file_path = Path(path)
    raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: config must be a mapping")
    unknown = sorted(set(raw) - _KNOWN)
    config = Config()
    config._base_dir = file_path.parent.resolve()  # noqa: SLF001 - used by resolve()
    if unknown:
        config.warnings.append(
            "ignored unknown config keys: " + ", ".join(unknown)
        )
    config.database = str(raw.get("database", config.database))
    config.output_dir = str(raw.get("output_dir", config.output_dir))
    hosts = raw.get("hosts_file")
    config.hosts_file = str(hosts) if hosts else None
    config.file_paths = [str(item) for item in raw.get("file_paths") or []]
    owners = raw.get("owners_file")
    config.owners_file = str(owners) if owners else None
    config.windows_json = [str(item) for item in raw.get("windows_json") or []]
    config.linux_json = [str(item) for item in raw.get("linux_json") or []]
    config.adcs_csv = [_adcs(item) for item in raw.get("adcs_csv") or []]
    config.tls_timeout_seconds = float(raw.get("tls_timeout_seconds", config.tls_timeout_seconds))
    config.horizon_days = int(raw.get("horizon_days", config.horizon_days))
    config.warn_days = int(raw.get("warn_days", config.warn_days))
    config.crit_days = int(raw.get("crit_days", config.crit_days))
    config.weak_rsa_bits = int(raw.get("weak_rsa_bits", config.weak_rsa_bits))
    config.notify_within_days = int(raw.get("notify_within_days", config.notify_within_days))
    webhook = raw.get("webhook") or {}
    if not isinstance(webhook, dict):
        raise ValueError("webhook must be a mapping")
    config.webhook_enabled = bool(webhook.get("enabled", False))
    config.webhook_url = str(webhook.get("url") or "")
    config.webhook_format = str(webhook.get("format") or "generic")
    return config


def _adcs(item) -> AdcsSource:
    if isinstance(item, str):
        return AdcsSource(path=item)
    if isinstance(item, dict) and item.get("path"):
        return AdcsSource(path=str(item["path"]), issuer=str(item.get("issuer") or ""))
    raise ValueError("adcs_csv entries must be a path or {path, issuer}")
