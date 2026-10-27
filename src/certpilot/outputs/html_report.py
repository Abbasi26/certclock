"""Self-contained HTML timeline. No remote assets, no telemetry."""

from __future__ import annotations

import html

from certpilot import __version__
from certpilot.dates import format_date, format_datetime
from certpilot.explain import BUCKET_LABELS, source_label
from certpilot.models import Report, ReportCert

_ORDER = ("expired", "within_7", "within_30", "within_90", "later")
_HORIZON = 120


def render_html(report: Report) -> str:
    counts = report.summary()
    generated = format_datetime(report.generated_at)
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>CertPilot timeline</title>",
        "<style>",
        _CSS,
        "</style>",
        "</head>",
        "<body>",
        "<header>",
        f'<p class="eyebrow">CertPilot {html.escape(__version__)} · local inventory · nothing leaves this machine</p>',
        "<h1>Certificate expiry timeline</h1>",
        "<p class=\"lede\">"
        f"Generated {html.escape(generated)}. "
        f"{counts['total']} certificates. "
        "Public TLS lifetimes are shrinking to 200 days (since March 2026) and 47 days by 2029, "
        "so the 7, 30, and 90 day windows are the ones worth watching."
        "</p>",
        "</header>",
        '<section class="stats">',
        _stat("Expired", counts["expired"], "expired"),
        _stat("7 days", counts["within_7"], "within_7"),
        _stat("30 days", counts["within_30"], "within_30"),
        _stat("90 days", counts["within_90"], "within_90"),
        _stat("Later", counts["later"], "later"),
        "</section>",
        _timeline(report),
        '<div class="toolbar">',
        '<label for="filter">Filter</label>',
        '<input id="filter" type="search" placeholder="Name, owner, source, or finding">',
        '<span id="shown"></span>',
        "</div>",
        "<main>",
    ]
    if not report.certificates:
        parts.append('<p class="empty">No certificates in this inventory yet.</p>')
    for bucket in _ORDER:
        rows = [cert for cert in report.certificates if cert.bucket == bucket]
        parts.append(f'<section class="bucket" id="{bucket}">')
        parts.append(
            f"<h2><span class=\"swatch {bucket}\"></span>{html.escape(BUCKET_LABELS[bucket])}"
            f"<em>{len(rows)}</em></h2>"
        )
        if not rows:
            parts.append('<p class="empty">Nothing in this window.</p>')
        for cert in rows:
            parts.append(_card(cert))
        parts.append("</section>")
    parts.append(_notes("Could not read", report.gaps))
    if report.warnings:
        parts.append('<section class="notes"><h2>Warnings</h2><ul>')
        for warning in report.warnings:
            parts.append(f"<li>{html.escape(warning)}</li>")
        parts.append("</ul></section>")
    parts.append("</main>")
    parts.append(
        "<footer>CertPilot wrote this file on this machine. It did not phone home. "
        "Buckets are expired, then 7, 30, and 90 days, then everything later. "
        "Dependency notes match an issuer already in the inventory.</footer>"
    )
    parts.append("<script>")
    parts.append(_JS)
    parts.append("</script>")
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def _stat(label: str, count: int, bucket: str) -> str:
    return (
        f'<a class="stat {bucket}" href="#{bucket}">'
        f"<strong>{count}</strong><span>{html.escape(label)}</span></a>"
    )


def _timeline(report: Report) -> str:
    dots: list[str] = []
    lanes: dict[int, int] = {}
    for cert in report.certificates:
        if cert.days_remaining < 0:
            continue
        days = min(cert.days_remaining, _HORIZON)
        slot = int(days / _HORIZON * 40)
        lane = lanes.get(slot, 0)
        lanes[slot] = lane + 1
        left = days / _HORIZON * 100
        top = 8 + (lane % 5) * 14
        title = html.escape(f"{cert.subject_cn}: {cert.days_remaining} days")
        dots.append(
            f'<a class="dot {cert.bucket}" style="left:{left:.2f}%;top:{top}px" '
            f'href="#cert-{_anchor(cert.fingerprint)}" title="{title}"></a>'
        )
    ticks = []
    for day, label in ((0, "today"), (7, "7d"), (30, "30d"), (90, "90d"), (120, "120d")):
        left = day / _HORIZON * 100
        ticks.append(
            f'<span class="tick" style="left:{left:.2f}%">{html.escape(label)}</span>'
        )
    return (
        '<section class="timeline" aria-label="Next 120 days">'
        '<div class="rail">' + "".join(dots) + "</div>"
        '<div class="axis">' + "".join(ticks) + "</div>"
        "</section>"
    )


def _card(cert: ReportCert) -> str:
    problems = "".join(
        "<li><span class=\"code\">"
        + html.escape(problem.code)
        + "</span> "
        + html.escape(problem.message)
        + "</li>"
        for problem in cert.problems
    ) or "<li>No structural findings. The expiry bucket above is the whole story.</li>"
    sources = "".join(
        "<li><span class=\"code\">"
        + html.escape(source_label(obs.source))
        + "</span> "
        + html.escape(obs.detail)
        + "</li>"
        for obs in cert.sources
    )
    sans = ", ".join(cert.sans) if cert.sans else "none"
    key = cert.key_type or "unknown key"
    if cert.key_size:
        key = f"{key} {cert.key_size}"
    signature = cert.signature_algorithm or "unknown signature"
    dependency = ""
    if cert.dependency_note:
        dependency = f'<p class="depend">{html.escape(cert.dependency_note)}</p>'
    note = ""
    if cert.owner_note:
        note = f'<p class="note">{html.escape(cert.owner_note)}</p>'
    owner = cert.owner or "unassigned"
    service = cert.service or "untagged"
    when = _when(cert)
    return (
        f'<article class="card {cert.bucket}" id="cert-{_anchor(cert.fingerprint)}" '
        f'data-search="{html.escape(cert.search_text)}">'
        f"<header><h3>{html.escape(cert.subject_cn)}</h3>"
        f'<p class="when">{html.escape(format_date(cert.not_after))} · {html.escape(when)}</p></header>'
        f'<p class="meta">{html.escape(owner)} · {html.escape(service)} · '
        f"{html.escape(key)} · {html.escape(signature)}</p>"
        f"{note}{dependency}"
        f"<p class=\"sub\">Subject {html.escape(cert.subject)}<br>"
        f"Issuer {html.escape(cert.issuer)}<br>"
        f"SAN {html.escape(sans)}<br>"
        f"Serial {html.escape(cert.serial)} · {html.escape(cert.fingerprint[:16])}</p>"
        f"<h4>Findings</h4><ul>{problems}</ul>"
        f"<h4>Seen at</h4><ul>{sources}</ul>"
        "</article>"
    )


def _when(cert: ReportCert) -> str:
    days = cert.days_remaining
    if days < 0:
        n = abs(days)
        unit = "day" if n == 1 else "days"
        return f"expired {n} {unit} ago"
    if days == 0:
        return "expires in less than 1 day"
    unit = "day" if days == 1 else "days"
    return f"in {days} {unit}"


def _notes(title: str, gaps) -> str:
    if not gaps:
        return ""
    items = "".join(
        f"<li><span class=\"code\">{html.escape(gap.source)}</span> "
        f"{html.escape(gap.detail)} - {html.escape(gap.message)}</li>"
        for gap in gaps
    )
    return f'<section class="notes"><h2>{html.escape(title)}</h2><ul>{items}</ul></section>'


def _anchor(fingerprint: str) -> str:
    return "".join(char for char in fingerprint if char.isalnum())[:24]


_CSS = """
:root {
  --paper: #efe6d6;
  --ink: #1c1915;
  --header: #1b2823;
  --card: #fbf7f0;
  --line: #d7c7b0;
  --muted: #5c564c;
  --expired: #8e2f2a;
  --within_7: #b45309;
  --within_30: #8a5a12;
  --within_90: #0f6e62;
  --later: #3e5348;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 16px/1.5 "Segoe UI", "Avenir Next", "Trebuchet MS", sans-serif;
}
header, main, footer { padding: 1.25rem clamp(1rem, 3vw, 2.5rem); }
header {
  background: var(--header);
  color: #f4efe6;
}
.eyebrow { letter-spacing: 0.12em; text-transform: uppercase; font-size: 0.72rem; margin: 0; color: #c9d5cf; }
h1 {
  font-family: Palatino, "Iowan Old Style", "Palatino Linotype", Georgia, serif;
  font-weight: 600;
  font-size: clamp(2rem, 4vw, 3.2rem);
  line-height: 1.05;
  margin: 0.35rem 0;
}
.lede { max-width: 46rem; color: #e4ddd2; margin: 0; }
.stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0.6rem;
  padding: 1rem clamp(1rem, 3vw, 2.5rem) 0;
}
.stat {
  background: var(--card);
  border: 1px solid var(--line);
  border-top: 4px solid var(--later);
  text-decoration: none;
  color: inherit;
  padding: 0.7rem 0.8rem;
}
.stat strong { display: block; font-size: 1.7rem; font-variant-numeric: tabular-nums; }
.stat span { color: var(--muted); font-size: 0.85rem; }
.stat.expired { border-top-color: var(--expired); }
.stat.within_7 { border-top-color: var(--within_7); }
.stat.within_30 { border-top-color: var(--within_30); }
.stat.within_90 { border-top-color: var(--within_90); }
.timeline { padding: 1rem clamp(1rem, 3vw, 2.5rem) 0; }
.rail {
  position: relative;
  height: 92px;
  background: linear-gradient(90deg, #f6e1d4, #f4edd8 25%, #e7f0ea 75%, #e4ebe6);
  border: 1px solid var(--line);
}
.dot {
  position: absolute;
  width: 12px;
  height: 12px;
  margin-left: -6px;
  border-radius: 50%;
  background: var(--later);
  box-shadow: 0 0 0 2px #fbf7f0;
}
.dot.expired { background: var(--expired); }
.dot.within_7 { background: var(--within_7); }
.dot.within_30 { background: var(--within_30); }
.dot.within_90 { background: var(--within_90); }
.axis { position: relative; height: 1.6rem; }
.tick { position: absolute; transform: translateX(-50%); font-size: 0.75rem; color: var(--muted); }
.toolbar {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  padding: 1rem clamp(1rem, 3vw, 2.5rem) 0;
}
.toolbar input {
  flex: 1;
  font: inherit;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--line);
  background: white;
  color: var(--ink);
}
h2 {
  font-family: Palatino, Georgia, serif;
  font-size: 1.45rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
h2 em { font-style: normal; color: var(--muted); font-family: "Segoe UI", sans-serif; font-size: 0.9rem; }
.swatch { width: 0.7rem; height: 0.7rem; display: inline-block; }
.swatch.expired { background: var(--expired); }
.swatch.within_7 { background: var(--within_7); }
.swatch.within_30 { background: var(--within_30); }
.swatch.within_90 { background: var(--within_90); }
.swatch.later { background: var(--later); }
.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-left: 6px solid var(--later);
  padding: 0.9rem 1rem;
  margin: 0 0 0.8rem;
}
.card.expired { border-left-color: var(--expired); }
.card.within_7 { border-left-color: var(--within_7); }
.card.within_30 { border-left-color: var(--within_30); }
.card.within_90 { border-left-color: var(--within_90); }
.card header { display: flex; justify-content: space-between; gap: 1rem; align-items: baseline; }
.card h3 { margin: 0; font-size: 1.15rem; }
.card h4 { margin: 0.8rem 0 0.2rem; font-size: 0.78rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }
.when { margin: 0; font-variant-numeric: tabular-nums; }
.meta, .sub, .depend, .note { margin: 0.35rem 0; }
.sub { color: var(--muted); font-size: 0.92rem; }
.depend { background: #f3ead2; padding: 0.45rem 0.6rem; }
.note { color: var(--muted); }
.code { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 0.78rem; color: var(--muted); }
ul { margin: 0.2rem 0 0; padding-left: 1.1rem; }
.empty { color: var(--muted); }
.notes { margin-top: 1rem; }
footer { color: var(--muted); font-size: 0.85rem; }
@media (max-width: 800px) {
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .card header { flex-direction: column; gap: 0.15rem; }
}
@media print {
  header { background: white; color: black; }
  .lede, .eyebrow { color: black; }
  .toolbar, footer { display: none; }
  .card { break-inside: avoid; }
}
"""

_JS = """
const input = document.getElementById("filter");
const cards = Array.from(document.querySelectorAll("[data-search]"));
const shown = document.getElementById("shown");
input.addEventListener("input", () => {
  const query = input.value.trim().toLowerCase();
  let count = 0;
  for (const card of cards) {
    const ok = !query || card.dataset.search.toLowerCase().includes(query);
    card.hidden = !ok;
    if (ok) count += 1;
  }
  shown.textContent = query ? count + " shown" : "";
});
"""
