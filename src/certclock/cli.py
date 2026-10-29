"""Command line for CertClock. Collection is read-only; only --send transmits anything."""

from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path

from certclock import __version__
from certclock.collectors.adcs import AdcsCollector
from certclock.collectors.files import FileCollector
from certclock.collectors.linux_json import LinuxJsonCollector
from certclock.collectors.tls import TlsCollector
from certclock.collectors.windows_store import WindowsStoreCollector
from certclock.config import Config, load_config
from certclock.dates import utcnow
from certclock.demo import format_summary, run_demo
from certclock.hosts import load_hosts
from certclock.inventory import Inventory
from certclock.outputs import write_reports
from certclock.outputs.checkmk import render_checkmk
from certclock.outputs.webhook import payload_for, preview_document, send_webhook
from certclock.pipeline import build_report, scan

_BUNDLED = (
    "Get-CertClockStore.ps1",
    "collect_linux_certs.py",
    "certclock-linux.yml",
)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1
    try:
        return args.func(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"certclock: {exc}", file=sys.stderr)
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certclock",
        description=(
            "Agentless certificate expiry radar. Reads certificates from TLS "
            "endpoints, files, Windows store exports, ADCS CSV, and Linux JSON, "
            "then puts them on one local timeline."
        ),
    )
    parser.add_argument("--version", action="version", version=f"certclock {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("demo", help="render a fictional inventory in under a minute")
    demo.add_argument("--out", default="certclock-demo", help="output directory")
    demo.add_argument(
        "--offline",
        action="store_true",
        help="skip the loopback TLS servers and use files plus imports only",
    )
    demo.set_defaults(func=_cmd_demo)

    scan_cmd = commands.add_parser("scan", help="collect everything in a config file and write reports")
    scan_cmd.add_argument("--config", required=True)
    scan_cmd.add_argument(
        "--send",
        action="store_true",
        help="after writing the preview, POST the webhook (off unless you pass this)",
    )
    scan_cmd.set_defaults(func=_cmd_scan)

    report = commands.add_parser("report", help="write reports from an existing inventory")
    _add_report_args(report)
    report.set_defaults(func=_cmd_report)

    checkmk = commands.add_parser("checkmk", help="print a Checkmk local check to stdout")
    _add_db_args(checkmk)
    checkmk.set_defaults(func=_cmd_checkmk)

    check = commands.add_parser(
        "check",
        help="pass/fail gate for CI or cron: exit 2 on CRIT/expired, 1 on WARN with --fail-on warn",
    )
    check.add_argument("--db", default=None, help="read an existing inventory")
    host_group = check.add_mutually_exclusive_group()
    host_group.add_argument("--host", action="append", default=[], help="host[:port] [sni]; repeatable")
    host_group.add_argument("--hosts-file", default=None, help="read endpoints from a hosts file")
    check.add_argument("--path", action="append", default=[], help="certificate file or directory; repeatable")
    check.add_argument("--owners", default=None)
    check.add_argument("--warn-days", type=int, default=30)
    check.add_argument("--crit-days", type=int, default=7)
    check.add_argument("--timeout", type=float, default=8.0)
    check.add_argument("--fail-on", default="crit", choices=("warn", "crit", "never"))
    check.add_argument("--format", default="text", choices=("text", "json", "markdown"))
    check.set_defaults(func=_cmd_check)

    notify = commands.add_parser("notify", help="preview or send a webhook")
    _add_db_args(notify)
    notify.add_argument("--url", default="")
    notify.add_argument("--format", default="generic", choices=("generic", "slack", "teams"))
    mode = notify.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--send", action="store_true", help="POST the payload. Implies a preview on stdout first.")
    notify.set_defaults(func=_cmd_notify)

    collect = commands.add_parser("collect", help="read TLS endpoints or certificate files into the inventory")
    collect_sub = collect.add_subparsers(dest="kind", required=True)
    tls = collect_sub.add_parser("tls")
    _add_db_args(tls, with_thresholds=False)
    tls.add_argument("--hosts", required=True)
    tls.add_argument("--timeout", type=float, default=8.0)
    tls.add_argument("--fresh", action="store_true")
    tls.set_defaults(func=_cmd_collect_tls)
    files_cmd = collect_sub.add_parser("files")
    _add_db_args(files_cmd, with_thresholds=False)
    files_cmd.add_argument("--path", action="append", required=True)
    files_cmd.add_argument("--fresh", action="store_true")
    files_cmd.set_defaults(func=_cmd_collect_files)

    import_cmd = commands.add_parser("import", help="import a collector export")
    import_sub = import_cmd.add_subparsers(dest="kind", required=True)
    windows = import_sub.add_parser("windows")
    _add_import_args(windows)
    windows.set_defaults(func=_cmd_import_windows)
    adcs = import_sub.add_parser("adcs")
    _add_import_args(adcs)
    adcs.add_argument("--issuer", default="", help="issuer DN used when the CSV has none")
    adcs.set_defaults(func=_cmd_import_adcs)
    linux = import_sub.add_parser("linux")
    _add_import_args(linux)
    linux.set_defaults(func=_cmd_import_linux)

    export = commands.add_parser("export-collectors", help="copy the PowerShell and Ansible collectors")
    export.add_argument("--dest", required=True)
    export.set_defaults(func=_cmd_export)
    return parser


def _add_db_args(parser: argparse.ArgumentParser, *, with_thresholds: bool = True) -> None:
    parser.add_argument("--db", required=True)
    parser.add_argument("--owners", default=None)
    if with_thresholds:
        parser.add_argument("--horizon-days", type=int, default=90)
        parser.add_argument("--warn-days", type=int, default=30)
        parser.add_argument("--crit-days", type=int, default=7)
        parser.add_argument("--within", type=int, default=30, help="notification window in days")
        parser.add_argument("--weak-rsa-bits", type=int, default=2048)


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    _add_db_args(parser)
    parser.add_argument("--out", required=True)


def _add_import_args(parser: argparse.ArgumentParser) -> None:
    _add_db_args(parser, with_thresholds=False)
    parser.add_argument("path")
    parser.add_argument("--fresh", action="store_true", help="wipe the inventory before this import")


def _cmd_demo(args: argparse.Namespace) -> int:
    result = run_demo(args.out, live=not args.offline)
    sys.stdout.write(format_summary(result))
    if result.elapsed_seconds > 60:
        print("certclock: demo exceeded 60 seconds", file=sys.stderr)
        return 1
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = scan(config, send=args.send)
    _print_scan(result.report, result.files, result.webhook_sent, config)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    report = _load_report(args)
    files = write_reports(report, args.out)
    _print_paths(files)
    return 0


def _cmd_checkmk(args: argparse.Namespace) -> int:
    sys.stdout.write(render_checkmk(_load_report(args)))
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    from certclock.check import EXIT_ERROR, render, run_check

    try:
        outcome = run_check(
            db=args.db,
            hosts=args.host,
            paths=args.path,
            owners=args.owners,
            warn_days=args.warn_days,
            crit_days=args.crit_days,
            timeout=args.timeout,
            fail_on=args.fail_on,
            hosts_file=args.hosts_file,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"certclock: {exc}", file=sys.stderr)
        return EXIT_ERROR
    sys.stdout.write(render(outcome, args.format))
    return outcome.exit_code


def _cmd_notify(args: argparse.Namespace) -> int:
    report = _load_report(args)
    preview = preview_document(report)
    print(json.dumps(preview, indent=2))
    if not args.send:
        print("webhook_sent: no")
        return 0
    url = args.url
    if not url:
        raise RuntimeError("pass --url to send. Nothing was sent.")
    status = send_webhook(url, payload_for(report, args.format))
    print(f"webhook_sent: yes\nhttp_status: {status}")
    return 0


def _cmd_collect_tls(args: argparse.Namespace) -> int:
    collector = TlsCollector(load_hosts(args.hosts), timeout=args.timeout)
    return _ingest(args.db, args.fresh, collector)


def _cmd_collect_files(args: argparse.Namespace) -> int:
    return _ingest(args.db, args.fresh, FileCollector(args.path))


def _cmd_import_windows(args: argparse.Namespace) -> int:
    return _ingest(args.db, args.fresh, WindowsStoreCollector([args.path]))


def _cmd_import_adcs(args: argparse.Namespace) -> int:
    return _ingest(args.db, args.fresh, AdcsCollector([{"path": args.path, "issuer": args.issuer}]))


def _cmd_import_linux(args: argparse.Namespace) -> int:
    return _ingest(args.db, args.fresh, LinuxJsonCollector([args.path]))


def _cmd_export(args: argparse.Namespace) -> int:
    destination = Path(args.dest)
    destination.mkdir(parents=True, exist_ok=True)
    bundled = files("certclock").joinpath("bundled")
    for name in _BUNDLED:
        target = destination / name
        target.write_bytes(bundled.joinpath(name).read_bytes())
        if name.endswith(".py"):
            target.chmod(0o755)
        print(target)
    return 0


def _ingest(database: str, fresh: bool, collector) -> int:
    with Inventory(database) as inventory:
        if fresh:
            inventory.wipe()
        inventory.ingest(collector.collect(), utcnow())
        count = len(inventory.certificates())
        warnings = inventory.warnings()
    print(f"certificates: {count}")
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


def _load_report(args: argparse.Namespace):
    config = Config(
        database=args.db,
        owners_file=getattr(args, "owners", None),
        horizon_days=getattr(args, "horizon_days", 90),
        warn_days=getattr(args, "warn_days", 30),
        crit_days=getattr(args, "crit_days", 7),
        notify_within_days=getattr(args, "within", 30),
        weak_rsa_bits=getattr(args, "weak_rsa_bits", 2048),
    )
    config._base_dir = Path.cwd()  # noqa: SLF001
    with Inventory(args.db) as inventory:
        return build_report(inventory, config, utcnow())


def _print_scan(report, files, sent: bool, config: Config) -> None:
    summary = report.summary()
    print(f"certificates: {summary['total']}")
    print(f"expired: {summary['expired']}")
    print(f"within_7: {summary['within_7']}")
    print(f"within_30: {summary['within_30']}")
    print(f"within_90: {summary['within_90']}")
    print(f"later: {summary['later']}")
    _print_paths(files)
    if sent:
        print("webhook_sent: yes")
    elif config.webhook_enabled:
        print("webhook_sent: no (pass --send to transmit the preview)")
    else:
        print("webhook_sent: no")
    for warning in report.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def _print_paths(files: dict[str, Path]) -> None:
    for label, path in files.items():
        print(f"{label}: {path}")
