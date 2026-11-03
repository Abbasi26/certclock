# Roadmap

CertClock stays a read-only, agentless inventory. Anything that changes a remote system needs its own explicit switch and a preview first.

## v0.2 (in progress)

- [x] `certclock check`: pass/fail gate with exit codes for CI, cron, and pre-change checks
- [x] GitHub Action (`uses: Abbasi26/certclock@<ref>`) with a Markdown job summary
- [x] `report.md` next to the HTML timeline, for issues, wikis, and chat tools
- [ ] STARTTLS for SMTP (`smtp://host:25`), IMAP, and LDAP endpoints
- [ ] Keep more than the latest snapshot and show what changed between two scans

## Later

- Read-only Intune SCEP/PKCS inventory
- Optional WinRM runner for the Windows store script that already ships
- Invoking `certutil -view` on a local CA, still read-only
- Container image for scheduled scans

## Good first issues

Small, self-contained tasks. Each one needs a test. Comment on the issue (or open one) before you start so two people do not do the same thing.

| Task | Where to start |
| --- | --- |
| `check --host` should accept `https://host:port/path` URLs and strip the scheme and path | `src/certclock/hosts.py` |
| `--hosts-file` option for `check`, reusing `load_hosts` | `src/certclock/check.py`, `src/certclock/cli.py` |
| `check --format checkmk` so one command can feed Checkmk and CI | `src/certclock/check.py` |
| [x] Show the issuing CA column in `report.md` | `src/certclock/outputs/markdown.py` |
| Add `--limit` to control how many rows `report.md` lists | `src/certclock/outputs/markdown.py` |
| Example GitHub workflow that checks a list of endpoints every night (`schedule:`) | `examples/` and README |
| Document `check` in the German summary at the end of the README | `README.md` |

## Not planned

- Issuing or renewing certificates (use an ACME client or your CA)
- Installing an agent on hosts
- Telemetry of any kind
