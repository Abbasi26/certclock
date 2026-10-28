# SPEC — CertClock (GitHub repo: certclock)

Restored from Cursor cloud-agent transcript.

## Original task prompt

Build v0.1 of **CertClock**, an agentless open-source certificate expiry radar that brings scattered certificate sources onto one timeline. Expired certificates are a top cause of major incidents, and public TLS lifetimes are shrinking (200 days since March 2026, 47 days by 2029). Follow ALL rules in uploads/gemeinsame_regeln.md. The prior-art research is in uploads/stand_der_technik.md (section E): single-source tools exist (PSPKI, x509-certificate-exporter, CertAlert, Certimate), but only expensive commercial software covers all sources together.

v0.1 scope (Python 3.11+ CLI `certclock`; may also ship a small PowerShell collector for Windows):
- Collectors, each pluggable:
  - network TLS endpoints from a hosts list (SNI, full chain, expiry, SAN, key size, signature algorithm, chain problems)
  - PEM/DER/PFX files in directories, metadata only and never private keys (password-protected PFX is skipped with a warning)
  - Windows certificate stores via a PowerShell collector script that exports JSON
  - Microsoft ADCS CA issued-certificates export (certutil -view CSV) as an import
  - Linux hosts via an included Ansible playbook that collects file metadata as JSON
- A normalized inventory in SQLite with dedupe by fingerprint, an owner/service tag from a YAML mapping, and dependency notes.
- Outputs:
  - a timeline HTML report (self-contained) with 7/30/90-day buckets
  - an ICS calendar file with reminders
  - a Checkmk local check / Prometheus textfile output
  - JSON/CSV
  - optional webhook notification (Teams/Slack/generic), off by default
- Chain/problem explanations in plain language (missing intermediate, SAN mismatch, weak key, SHA1).
- `certclock demo` that spins up fictional data (and optionally local test TLS servers with self-generated short-lived certs) and renders the report in under 60 s.
- pytest suite with generated test certificates; no network access needed in CI.
