# Security policy

CertClock reads certificate metadata and writes a local report. It is not a scanner you point at networks you do not administer.

## Reporting a vulnerability

If this project has a public repository, use its private security advisory. Do not open a public issue for a vulnerability. There is no bug-bounty program.

## What the tool is allowed to do

- Read TLS handshakes, certificate files, and the JSON or CSV you give it
- Write the SQLite inventory and the report directory on the machine where it runs
- POST a webhook only when you pass `--send` and only to an `http://` or `https://` URL you set

It does not renew certificates, change stores, or install trust. Password-protected PKCS#12 files are skipped rather than unlocked. Private-key PEM blocks are not stored. The Windows script opens stores read-only and does not export keys.

## Data

The database and the reports contain host names, file paths, subjects, and expiry dates. Keep them with the same care as any other inventory export. CertClock does not send that data anywhere except the webhook you explicitly enable.

Do not commit webhook URLs, `certclock.db`, or report directories. The example configuration ships with `webhook.enabled: false` and an empty URL.
