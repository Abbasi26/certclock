# Changelog

## Unreleased

- `long_validity` finding: end-entity certificates valid for longer than `max_validity_days` (default 100, `0` off; `--max-validity-days` on the CLI). The message names the CA/Browser Forum SC-081v3 limit for the issue date (398/200/100/47 days) and the ADCS certificate template. `check` lists them without changing the exit code

### Fixed

- `check --db` with `--host`/`--path` no longer writes to the production database; ad-hoc data is collected into a temporary database and merged in memory
- Certificates from the production DB and ad-hoc inputs are deduplicated by SHA-256 fingerprint with observations merged (e.g., `file` + `tls` sources combined)
- Cross-database issuer matching works: a leaf from `--path` with issuer only in `--db` gets `issuer_expires_first` finding
- Unreadable or corrupt `--db` file now exits with code 3 (catches `sqlite3.Error` explicitly)

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