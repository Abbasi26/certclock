# CertClock

[![CI](https://github.com/Abbasi26/certclock/actions/workflows/ci.yml/badge.svg)](https://github.com/Abbasi26/certclock/actions/workflows/ci.yml)

CertClock is an agentless certificate expiry radar. It reads the certificate sources you already have and puts them on one local timeline.

A gateway certificate expired overnight, and the same certificate was also sitting in a file on a Linux host. It was issued by an internal CA that itself expires in 70 days. A second server certificate still has 200 days left, but clients will stop trusting it when that CA expires. Tools that watch only TLS endpoints, only files, or only the CA each see one piece. CertClock records all of them, deduplicates by fingerprint, and says which certificate depends on which issuer.

Public TLS lifetimes are already down to 200 days (since 15 March 2026) and are scheduled to reach 47 days in 2029 ([CA/Browser Forum baseline requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)). The 7, 30, and 90 day windows are the ones operations teams actually page on.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
certclock demo
```

That writes `certclock-demo/` in under a minute. Open `certclock-demo/index.html`. The data is fictional (`example.test`, Example Laboratory). Add `--offline` to skip the loopback TLS servers. Nothing is sent anywhere. `webhook_sent: no` in the summary means the preview file was written and not posted.

## Gate a pipeline with `certclock check`

`check` is the one-liner for CI, cron, and "is it safe to change this?" moments. It collects ad hoc (or reads an existing `--db`), prints the certificates that need attention, and sets the exit code:

| Exit code | Meaning |
| --- | --- |
| `0` | Nothing at or past the failing level |
| `1` | Something is at WARN (default 30 days), only with `--fail-on warn` |
| `2` | Something is at CRIT (default 7 days) or already expired |
| `3` | Usage or input error |

```bash
certclock check --host vpn.example.test:443 --path /etc/ssl/certs/app.pem
certclock check --db certclock.db --fail-on warn --format json
certclock check --host mail.example.test:443 --warn-days 45 --crit-days 14 --format markdown
```

Example text output:

```text
CRIT: 3 certificates, 1 expired, 1 within 7 days, 1 within 30 days
  CRIT    -3d  gone.example.test  (/etc/ssl/certs/gone.pem)
  CRIT     4d  edge.example.test  (10.0.0.8:443 SNI edge.example.test)
  WARN    20d  soon.example.test  (/etc/ssl/certs/soon.pem)
```

### GitHub Action

```yaml
- uses: Abbasi26/certclock@main   # pin a tag or commit once v0.2 is released
  with:
    hosts: |
      www.example.test:443
      api.example.test:443
    paths: deploy/certs
    warn-days: "30"
    crit-days: "7"
    fail-on: crit        # warn, crit, or never
```

The step writes the Markdown report to the job summary and fails the job on CRIT. `exit-code` is available as a step output.

## Real usage

One config file runs every collector that has an input, replaces the local SQLite snapshot, and writes the reports:

```bash
certclock scan --config examples/certclock.yml
```

The example hosts list is comments only, so that command does not open a network connection. Point `hosts_file` and `file_paths` at your own inventory when you are ready.

Reports in the output directory:

| File | What it is |
| --- | --- |
| `index.html` | Self-contained timeline with expired, 7, 30, 90 day, and later buckets |
| `calendar.ics` | One event per certificate inside the horizon (default 90 days), with 30, 7, and 1 day reminders |
| `checkmk.out` | Checkmk local-check text. WARN at 30 days, CRIT at 7 days or already expired |
| `certclock.prom` | Prometheus textfile snapshot |
| `inventory.json`, `inventory.csv` | The same rows for anything else |
| `report.md` | Markdown summary and table, sorted by expiry, for issues, wikis, and chat |
| `webhook-preview.json` | The notification body. Not sent |

You can also collect one source at a time and report later:

```bash
certclock collect tls --db certclock.db --hosts hosts.txt
certclock collect files --db certclock.db --path /etc/ssl/certs --path /etc/pki/tls/certs
certclock import windows --db certclock.db stores.json
certclock import adcs --db certclock.db issued.csv --issuer "CN=Example Laboratory Issuing CA"
certclock import linux --db certclock.db web01.json
certclock report --db certclock.db --out certclock-out --owners owners.yml
certclock checkmk --db certclock.db --owners owners.yml
```

`scan` starts from an empty database. `collect` and `import` replace previous rows from that same source and leave the others. Delete the database for a full reset. The database is the latest snapshot, not a history of past scans.

### TLS endpoints

`hosts.txt` is one endpoint per line. `#` comments are ignored.

```text
vpn.example.test:443
10.0.0.8:8443 vpn.example.test
[2001:db8::10]:443 vpn.example.test
```

The optional second field is the SNI name and the name checked against the SAN (or the common name, if the certificate has no SAN). CertClock records the leaf and every other certificate the handshake presented. On Python 3.13+ it uses `SSLSocket.get_unverified_chain()`. On older 3.11 and 3.12 it uses `openssl s_client -showcerts` when `openssl` is on `PATH`, and otherwise keeps the leaf only. A leaf-only read is not reported as a missing intermediate, because the chain was not seen.

### Files

Directories are walked for `.pem`, `.crt`, `.cer`, `.der`, `.pfx`, and `.p12`. A file you pass directly is read even if the suffix is unusual. Certificate blocks are stored. `PRIVATE KEY` blocks are ignored and called out in a warning. Password-protected PKCS#12 is skipped. CertClock does not prompt for a password and does not try one. Export the public certificates yourself (`openssl pkcs12 -nokeys`) if you need them in the inventory. Files larger than 2 MB are skipped.

### Windows certificate stores

v0.1 does not open WinRM. Run the read-only script on the Windows host, copy the JSON back, and import it. The script opens stores with `ReadOnly` and `OpenExistingOnly`. It writes the SHA-256 thumbprint, subject, issuer, serial, dates, SAN, key type, key size, signature algorithm, and `has_private_key`. It does not write the key.

```powershell
pwsh -File src/certclock/bundled/Get-CertClockStore.ps1 -OutFile stores.json
```

`certclock export-collectors --dest ./collectors` copies that script, the Linux collector, and the Ansible playbook out of the installed package.

### ADCS

Produce a CSV on the CA with `certutil -view`. This is the shape that imports cleanly; column labels are matched loosely (`Request Common Name` and `RequestCommonName` are the same idea), and a `CertUtil:` footer is ignored:

```text
certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,RequestCommonName,RequestDisposition,CertificateTemplate,SerialNumber,NotBefore,NotAfter" csv > issued.csv
```

Rows whose disposition is present and not issued (`20`) are skipped, so a revoked certificate does not sit on the renewal timeline. Dependency notes need the issuer DN. Add an issuer column, pass `--issuer`, or set `issuer` under `adcs_csv` in the config. CertClock does not run `certutil` and does not load PSPKI.

### Linux files

The Ansible playbook is read-only apart from uploading its own script to a temporary directory (Ansible removes that copy) and writing JSON on the controller:

```bash
certclock export-collectors --dest ./collectors
ansible-playbook collectors/certclock-linux.yml -i inventory.ini
certclock import linux --db certclock.db ./certclock-linux/web01.example.test.json
```

Inventory group name: `certclock_linux`. Default search paths are `/etc/ssl` and `/etc/pki`. Override `certclock_paths`. The remote script shells out to `openssl`, prints JSON on stdout, and never prints a private key. You can run `collect_linux_certs.py` by hand on a host without Ansible.

The same playbook is also packaged as the Ansible collection `abbasi26.certclock` (sources in [`ansible/collection`](ansible/collection), built by `ansible/build-collection.sh`). Once it is published on Ansible Galaxy: `ansible-galaxy collection install abbasi26.certclock`, then `ansible-playbook abbasi26.certclock.certclock_linux -i inventory.ini`.

### Owners and dependencies

`owners.yml` is applied when the report is built, so editing it does not require another collection. The first matching rule wins. Every rule needs a non-empty `match` map. Unknown match keys are an error.

Match keys: `common_name`, `common_name_contains`, `subject_contains`, `issuer_contains`, `san_contains`, `san_suffix`, `source`, `source_detail_contains`, `serial`, and `any: true` as an explicit catch-all.
If present, `any` must be the YAML boolean `true`; other values are rejected.

When one certificate's issuer is another certificate in the inventory, the report says so. Matching prefers the authority key identifier, then the issuer DN. If the issuer expires before the leaf, the finding is `issuer_expires_first`: clients stop trusting the leaf when the CA expires. A TLS handshake that omitted an intermediate you have is `chain_omits_issuer`. A handshake that omitted an issuer you do not have is `missing_intermediate`. A self-signed root is not flagged just because the server did not send it. Other findings:

| Code | Meaning |
| --- | --- |
| `expired`, `expires_within_7`, `expires_within_30`, `expires_within_90` | The tightest expiry window |
| `san_mismatch` | The name you connected with is not in the SAN (or the CN, if there is no SAN) |
| `weak_key` | RSA shorter than 2048 bits (configurable), EC shorter than 256 bits, or any DSA key |
| `sha1` | Signature algorithm is SHA-1 |
| `self_signed` | End-entity certificate, or a self-signed certificate we cannot tell is a CA |
| `issuer_not_in_inventory` | No chain was observed and the issuer was not collected, so the dependency cannot be timed |

### Checkmk and Prometheus

`certclock checkmk` prints local-check lines and exits 0. Checkmk reads the status number, not the exit code. Put a shell wrapper on the agent:

```sh
#!/bin/sh
exec certclock checkmk --db /var/lib/certclock/certclock.db --owners /etc/certclock/owners.yml
```

`certclock.prom` is a textfile for `node_exporter`. Rewrite it on a schedule. CertClock does not listen for scrapes.

### Webhook

Webhooks are off. `scan` writes `webhook-preview.json` and does not post it. `--send` is the switch that transmits, and it still prints the preview first.

```bash
certclock notify --db certclock.db --preview
certclock notify --db certclock.db --send --url https://hooks.example.test/certclock --format slack
certclock scan --config certclock.yml --send
```

`scan --send` also requires `webhook.enabled: true` and `webhook.url` in the config. Formats are `generic` (JSON), `slack` (`{"text": ...}`), and `teams` (MessageCard). The URL must be `http://` or `https://`. Only certificates inside `notify_within_days` (default 30), including already expired ones, are included.

## Required permissions

CertClock does not change remote systems. The only write outside the output directory and the SQLite file is a webhook POST, and only with `--send`.

| Source | What it needs |
| --- | --- |
| TLS | A network path to `host:port`. No certificate, no login |
| Files | Read access to the certificate files. A private key in the same PEM is ignored |
| Windows script | Permission to open the store read-only. LocalMachine stores usually need an administrator. The script does not export keys |
| ADCS CSV | Whoever runs `certutil -view` needs read access on the CA. CertClock only reads the file they produce |
| Ansible | SSH as an account that can read the certificate paths. `become` is off. Ansible stages the collector script in a temp directory on the host |
| Webhook | Outbound HTTP from the machine running CertClock, and only after `--send` |

Treat `certclock.db` and the reports as an inventory: they contain host names, paths, and certificate metadata.

## How this differs from existing tools

Each source already has a specialist. CertClock is the read-only join, not a replacement for issuing or for a full CLM suite.

| Tool | What it already does | What CertClock does not copy |
| --- | --- | --- |
| [CertAlert](https://www.redkestrel.co.uk/products/certalert/faq) | Commercial TLS discovery, reports, and mail | No CA database, no stores, no file inventory |
| [Certimate](https://github.com/certimate-go/certimate) | ACME issuance and deployment | Not an inventory of internal certificates |
| [x509-certificate-exporter](https://github.com/enix/x509-certificate-exporter) | Prometheus metrics for files and Kubernetes secrets | No MS-CA, no Windows stores; expects Prometheus |
| [blackbox_exporter](https://github.com/prometheus/blackbox_exporter) | Probe a TLS endpoint | No inventory and no other sources |
| [PSPKI](https://github.com/Crypt32/PSPKI) | Deep ADCS queries such as issued-request filters | A library, not a timeline. CertClock imports `certutil` CSV instead of wrapping PSPKI |
| [No-Cert-Left-Behind](https://github.com/SamErde/No-Cert-Left-Behind) | ADCS expiry report by template | ADCS only |
| [Keyfactor Command](https://www.keyfactor.com/products/command/) | Commercial discovery, inventory, alerts, and renewal, with orchestrator agents | CertClock does not renew certificates and does not install an agent |
| [Intune Certificate Connector](https://learn.microsoft.com/en-us/intune/device-configuration/certificates/pkcs-profiles) | Issues SCEP and PKCS certificates | No expiry radar. Intune inventory is not in v0.1 |

## Development

How to contribute is in [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
pip install -e ".[dev]"
pytest -q
```

The pytest suite generates its own certificates and talks only to `127.0.0.1` when it exercises TLS. The Windows script has a Pester 5 test (`tests/powershell/Get-CertClockStore.Tests.ps1`) that builds a certificate in process and checks the export has no private key.

Collectors are objects with `collect() -> CollectionResult`. `Inventory.ingest` accepts any object that returns that shape, which is how a caller adds a source the CLI does not know. The built-in collectors are also registered as `certclock.collectors` entry points. `scan` itself runs the built-ins selected by the config file; it does not download or execute third-party code.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for v0.2 progress and good first issues.

- Read-only Intune SCEP/PKCS inventory
- An optional WinRM runner for the Windows script that already ships
- STARTTLS for SMTP, IMAP, and LDAP
- Invoking `certutil` on a local CA, still read-only
- Keeping more than the latest snapshot

## Limitations

- No renewal, no store changes, no remote remediation
- No Intune, no Kubernetes, no STARTTLS in v0.1
- Windows and Linux hosts are collected by the script or playbook, then imported. CertClock does not open WinRM or SSH itself
- ADCS is a CSV import, not a live CA query
- Issuer linking is the authority key identifier when we have one, otherwise a normalized issuer/subject string. Odd DN encodings can miss a link
- Password-protected PKCS#12 is skipped
- A TLS stack that cannot show the chain (no `get_unverified_chain`, no `openssl`) records the leaf and does not claim the intermediate was missing
- The Checkmk file is local-check text, not a compiled check plugin
- Webhook delivery is a single POST with no retry

## Status

Version 0.2.0, early but usable. Python package `certclock` (CLI `certclock`). MIT licensed. Every push runs the test suite in GitHub Actions (`.github/workflows/ci.yml`).

## Install

```sh
pip install .
```

## Tests

```sh
python -m pytest   # plus: pwsh -c "Invoke-Pester tests/powershell"
```

## License

MIT. Copyright (c) 2026 Wasaf Abbasi.

## Kurzfassung (Deutsch)

CertClock ist ein lokales Kommandozeilenwerkzeug ohne Agenten. Es sammelt öffentliche Zertifikatsdaten von TLS-Endpunkten, PEM/DER/PFX-Dateien, einem nur lesenden PowerShell-Export der Windows-Zertifikatsspeicher, einem `certutil -view`-CSV der Microsoft-CA und einem Ansible-Lauf für Linux-Dateien. Dieselbe Zertifikatsdatei wird über den SHA-256-Fingerabdruck zusammengeführt. Ein YAML-Mapping setzt Owner und Dienst. Der Bericht zeigt, welches Blatt von welcher ausstellenden CA abhängt, auch wenn die CA früher abläuft als das Blatt. Ausgaben sind eine HTML-Zeitleiste (7/30/90 Tage), eine ICS-Datei mit Erinnerungen, Checkmk-Local-Check-Text, eine Prometheus-Textdatei, JSON und CSV. Private Schlüssel werden nicht gespeichert, passwortgeschützte PFX-Dateien werden ausgelassen. Es gibt keine Telemetrie. Ein Webhook geht nur mit `--send` hinaus. `certclock demo` zeigt den Ablauf mit erfundenen `example.test`-Daten in unter einer Minute, ohne echte Infrastruktur.
