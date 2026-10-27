# Contributing

CertPilot is a local, read-only inventory. Changes should stay that way unless a new action has its own explicit switch and prints a preview before it does anything.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Python 3.11 or newer. The Windows collector is tested with Pester 5:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Force -SkipPublisherCheck -Scope CurrentUser
Invoke-Pester -Path tests/powershell -CI
```

## Project rules

- Code, comments, and documents are in English. The README keeps a short German summary at the end.
- Do not add telemetry, phone-home endpoints, or real host names. Demos and tests use `example.test` and other obviously fictional names.
- Do not commit secrets, private keys, or password-protected bundles that the tests need to open. Tests generate certificates themselves.
- Collectors return public certificate material only. A new collector that can see a private key must drop it and warn.
- Do not document a feature the command does not implement.
- PowerShell files stay ASCII, or UTF-8 with BOM if a non-ASCII character is unavoidable.

## Pull requests

Describe what a user can now see in the timeline or the exports. Run pytest. If you touch `Get-CertPilotStore.ps1`, run the Pester file too.
