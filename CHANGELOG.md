# Changelog

## 0.1.0 - 2026-10-21

First release.

- TLS hosts, PEM/DER/PFX files, a Windows certificate-store JSON export, an ADCS `certutil -view` CSV, and Linux JSON from the included Ansible playbook
- SQLite inventory deduplicated by SHA-256 of the public certificate, with owner rules and issuer dependency notes
- HTML timeline (expired, 7, 30, 90 days, later), ICS reminders, Checkmk local-check text, Prometheus textfile, JSON, and CSV
- Webhook preview for generic JSON, Slack, and Teams. Nothing is sent unless `--send` is passed
- `certpilot demo` builds a fictional inventory, optionally scans loopback TLS servers, and writes the reports
- pytest coverage that generates its own certificates and does not need an external network
