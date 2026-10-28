# Changelog

## 0.2.0 - 2026-10-28

- `certclock check`: CI and cron gate with exit codes 0/1/2/3, ad hoc `--host`/`--path` collection or `--db`, `--fail-on warn|crit|never`, and `text`, `json`, or `markdown` output
- GitHub Action (`action.yml`) that runs `check` and writes the Markdown report to the job summary
- `report.md`: Markdown summary written next to the other reports
- ROADMAP.md with good first issues, issue forms, and a pull request template
- Renamed the project from `certpilot` to `certclock`: package, CLI, environment variables, files and docs. Entries below use the old name.

## 0.1.0 - 2026-10-21

First release.

- TLS hosts, PEM/DER/PFX files, a Windows certificate-store JSON export, an ADCS `certutil -view` CSV, and Linux JSON from the included Ansible playbook
- SQLite inventory deduplicated by SHA-256 of the public certificate, with owner rules and issuer dependency notes
- HTML timeline (expired, 7, 30, 90 days, later), ICS reminders, Checkmk local-check text, Prometheus textfile, JSON, and CSV
- Webhook preview for generic JSON, Slack, and Teams. Nothing is sent unless `--send` is passed
- `certpilot demo` builds a fictional inventory, optionally scans loopback TLS servers, and writes the reports
- pytest coverage that generates its own certificates and does not need an external network
