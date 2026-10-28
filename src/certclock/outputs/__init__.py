"""Write every report artifact into one directory."""

from __future__ import annotations

import json
from pathlib import Path

from certclock.models import Report
from certclock.outputs.checkmk import render_checkmk
from certclock.outputs.html_report import render_html
from certclock.outputs.ics import render_ics
from certclock.outputs.prometheus import render_prometheus
from certclock.outputs.tabular import render_csv, render_json
from certclock.outputs.webhook import preview_document


def write_reports(report: Report, output_dir: str | Path) -> dict[str, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    files = {
        "html": directory / "index.html",
        "ics": directory / "calendar.ics",
        "checkmk": directory / "checkmk.out",
        "prometheus": directory / "certclock.prom",
        "json": directory / "inventory.json",
        "csv": directory / "inventory.csv",
        "webhook_preview": directory / "webhook-preview.json",
    }
    files["html"].write_text(render_html(report), encoding="utf-8")
    files["ics"].write_text(render_ics(report), encoding="utf-8")
    files["checkmk"].write_text(render_checkmk(report), encoding="utf-8")
    files["prometheus"].write_text(render_prometheus(report), encoding="utf-8")
    files["json"].write_text(render_json(report), encoding="utf-8")
    files["csv"].write_text(render_csv(report), encoding="utf-8")
    files["webhook_preview"].write_text(
        json.dumps(preview_document(report), indent=2) + "\n",
        encoding="utf-8",
    )
    return files
