# `certclock check --format checkmk` — Checkmk Local-Check Output for CI and Monitoring

## Problem Statement

The `certclock check` command supports `--format text|json|markdown` (CLI line 101) and produces exit codes 0/1/2/3 suitable for CI gates. The separate `certclock checkmk` command prints Checkmk local-check text (exit 0 always; status is embedded in the output). Users who want to feed Checkmk **and** use the CI gate in one command need two invocations:

```bash
certclock check --db certclock.db --fail-on crit          # CI gate
certclock checkmk --db certclock.db --owners owners.yml  # Checkmk local check
```

ROADMAP.md lists "check --format checkmk so one command can feed Checkmk and CI" as a beginner-friendly issue.

## Goals

- Add `checkmk` to the `--format` choices of `certclock check`.
- When `--format checkmk` is selected, render the Checkmk local-check format via the existing `render_checkmk(report)` function (from `certclock.outputs.checkmk`).
- Preserve the existing `check` exit-code semantics (0/1/2/3 based on `--fail-on`).
- One command replaces both `check` (for CI) and `checkmk` (for Checkmk local-check output).
- No changes to `certclock checkmk` command; it remains for users who only need the Checkmk output.

## Non-Goals

- Changing the Checkmk output format (it already matches the `certclock checkmk` output).
- Adding new CLI flags or changing `--fail-on` / `--warn-days` / `--crit-days` behaviour.
- Modifying `render_checkmk` or the `checkmk` command.
- Supporting `--hosts-file` or URL parsing for `--host` (those are separate planned/in-flight PRs).

## Proposed Architecture

The change is confined to the existing render dispatcher in `check.py` and the CLI argument definition in `cli.py`.

1. **CLI (`src/certclock/cli.py`)**: Add `"checkmk"` to the `--format` choices for the `check` command (line 101).
2. **Check module (`src/certclock/check.py`)**:
   - Import `render_checkmk` from `certclock.outputs.checkmk`.
   - In `render(outcome, fmt)`, add a branch for `fmt == "checkmk"` that calls `render_checkmk(outcome.report)`.
3. **Tests (`tests/test_check.py`)**: Add `test_check_format_checkmk` that:
   - Creates a temp PEM with a certificate expiring within the CRIT window.
   - Runs `main(["check", "--path", ..., "--format", "checkmk"])`.
   - Asserts exit code is `EXIT_CRIT` (2).
   - Asserts stdout contains Checkmk lines: a summary line (`2 "CertClock summary" ...`) and at least one service line (`2 "Cert ..." expires_in_days=...;; ...`).
4. **CHANGELOG.md**: Add one-line entry under `## Unreleased` / `### Added`.

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| Add a separate `--checkmk` flag to `check` | Inconsistent with existing `--format` pattern (`text`, `json`, `markdown`). A format choice is the idiomatic extension. |
| Make `check` always output Checkmk when `--format checkmk` and change exit code to 0 | Would break CI gate semantics. Exit codes must remain 0/1/2/3 per `--fail-on`. Checkmk reads status from the text, not the process exit code. |
| Call `certclock checkmk` internally via subprocess | Unnecessary process spawn; `render_checkmk` is a pure function already available. |
| Duplicate the Checkmk rendering logic in `check.py` | Violates DRY; `render_checkmk` is the canonical renderer for this format. |

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Test flakiness from timestamp-dependent expiry | Use `mint()` with fixed `not_after` relative to `utcnow()` (existing pattern in `test_check.py`). |
| Exit code mismatch between CI and Checkmk expectations | Document in README that Checkmk wrapper scripts should ignore the process exit code and parse the status number from the local-check text. No code change needed. |
| Import cycle if `check.py` imports from `outputs.checkmk` | No import cycle: `outputs.checkmk` imports only from `models`; `check.py` imports from `models`, `pipeline`, `outputs.markdown`. |
| Security / scalability impact | No new I/O or network surface; no scalability impact — pure format dispatch change. |
| Output differs from standalone `certclock checkmk` | Both call the same `render_checkmk(report)`; output is identical. Test asserts the line format. |

## Acceptance Criteria

1. `certclock check --path <file> --format checkmk` prints Checkmk local-check lines to stdout.
2. Exit code follows `--fail-on` (0/1/2/3), not forced to 0.
3. Output contains a summary line starting with `2 "CertClock summary" ...` (or 1/0 depending on worst status).
4. Output contains at least one service line matching `2 "Cert <name>" expires_in_days=<n>;<warn>;<crit>;; ...`.
5. `pytest -q` passes (all existing + new test).
6. `ruff check .` passes.
7. CHANGELOG.md updated under `## Unreleased`.

---

## Detailed Implementation Plan

### Target Scope & File Boundary

**Modified files:**
- `src/certclock/cli.py` — add `"checkmk"` to `--format` choices.
- `src/certclock/check.py` — import `render_checkmk` and add dispatch branch.
- `tests/test_check.py` — add `test_check_format_checkmk`.
- `CHANGELOG.md` — one-line entry under `## Unreleased` / `### Added`.

**No other files changed.**

### Actionable Steps

#### 1. `src/certclock/cli.py` — Extend `--format` choices (line 101)

```python
check.add_argument("--format", default="text", choices=("text", "json", "markdown", "checkmk"))
```

#### 2. `src/certclock/check.py` — Import and dispatch

**Add import at top (after line 30):**
```python
from certclock.outputs.checkmk import render_checkmk
```

**Modify `render(outcome, fmt)` (lines 303–308):**
```python
def render(outcome: CheckOutcome, fmt: str) -> str:
    if fmt == "json":
        return render_json_outcome(outcome)
    if fmt == "markdown":
        return render_markdown(outcome.report)
    if fmt == "checkmk":
        return render_checkmk(outcome.report)
    return render_text(outcome)
```

#### 3. `tests/test_check.py` — New test

**Add near line 150 (after parametrized format test):**
```python
def test_check_format_checkmk(tmp_path: Path, capsys):
    """--format checkmk produces Checkmk local-check lines and preserves exit code."""
    # Certificate expiring in 3 days -> CRIT (default crit-days=7)
    _cert_file(tmp_path, "critical.example.test", 3)

    code = main(["check", "--path", str(tmp_path), "--format", "checkmk"])
    assert code == EXIT_CRIT

    out = capsys.readouterr().out
    # Summary line
    assert '2 "CertClock summary"' in out
    assert "expired=0|within_7=1|within_30=1|within_90=1|total=1" in out
    # Service line for the certificate
    assert '2 "Cert critical.example.test"' in out
    assert "expires_in_days=3;30;7;;" in out
```

#### 4. `CHANGELOG.md` — Entry under `## Unreleased` / `### Added`

```markdown
- `certclock check --format checkmk` renders Checkmk local-check text while preserving CI exit codes (0/1/2/3).
```

### Error Behaviour

- Invalid `--format` value: `argparse` rejects before `main` runs → exit 2 (usage error).
- `render_checkmk` receives a valid `Report`; no new error paths introduced.
- All existing error handling in `_cmd_check` (lines 202–221) unchanged.

### Test Cases (pytest)

| Test | Scenario | Expected |
|------|----------|----------|
| `test_check_format_checkmk` | Temp PEM with cert at 3 days, `--format checkmk` | Exit `EXIT_CRIT` (2); stdout has summary + service line with `expires_in_days=3;30;7;;` |
| Existing `test_check_formats_do_not_leak_keys` (parametrized) | Also runs with `fmt="checkmk"` via parametrize | No private key material in output |

*Note:* The parametrized test at line 150 should be updated to include `"checkmk"` in the `fmt` values to ensure the new format doesn't leak keys.

### Documentation Changes

- **README.md**: No change needed (the `check` command documented with `--format text|json|markdown`; adding `checkmk` is a natural extension).
- **CHANGELOG.md**: One entry under `## Unreleased` / `### Added` (see above).
- No other docs affected.

### Verification Checklist

- [ ] `pytest -q` passes (all existing + new test).
- [ ] `ruff check .` passes.
- [ ] Manual smoke test:
  ```bash
  python -m certclock check --path certclock-demo/certclock.db --format checkmk
  # Verify output contains summary and service lines
  ```
- [ ] No import errors, no runtime errors.

### Implementation Notes (for the implementer)

- The `render_checkmk` function expects a `Report` object. `outcome.report` is exactly that.
- The `checkmk` format does not use the `CheckOutcome.worst` or `exit_code`; it computes its own status per-certificate inside `render_checkmk` (via `_status`). This is intentional — Checkmk local checks embed status in the text.
- The CLI `--fail-on` and exit codes remain unchanged; they control the **process** exit code for CI. Checkmk agent ignores process exit code and parses the status number from each line.
- Keep the change minimal: only the three files listed above.