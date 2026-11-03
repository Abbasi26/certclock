# `check --db` Opens the Database Read-Only

## Problem Statement

The `certclock check` command documents that `--db` reads an existing inventory or collects ad hoc into a throwaway database (CLI help line 86, `check.py` docstring lines 10–12). However, when `--host` or `--path` arguments are provided alongside `--db`, the implementation writes the collected observations into that same database file (`check.py:93–98`). This replaces the `tls`/`tls-chain` or `file` sources in the production inventory (`inventory.py:100–112`, `tls.py:27`), potentially deleting legitimate TLS or file observations from a scheduled scan.

A one-off `check` run can therefore corrupt the production snapshot that a cron job relies on.

## Goals

- `certclock check --db <file>` **without** `--host`/`--path`: read the existing inventory read-only; no writes.
- `certclock check --db <file> --host ...` or `--path ...`: collect the ad-hoc endpoints/files into a **temporary** database, merge with the existing inventory in memory for the check, and **never write back** to the production database file.
- Existing behaviour for `check --host`/`--path` without `--db` (throwaway temp DB) remains unchanged.
- All other commands (`scan`, `collect`, `import`, `report`, `checkmk`, `notify`) are unaffected.

## Non-Goals

- Changing the `Inventory` class to support a read-only mode (the fix is local to `check.py`).
- Adding a new `--read-only` flag.
- Modifying the database schema or any collector.

## Proposed Architecture

The `run_check` function in `check.py` already creates a temporary directory when `db` is `None` (line 91–92). The fix extends this pattern:

1. If `db` is provided **and** (`hosts` or `paths` are non-empty):
   - Open the production database **read-only** (or open normally but do not call `ingest` on it).
   - Create a temporary database in the existing scratch directory.
   - Ingest `--host`/`--path` data into the temporary database.
   - Build the report from a **merged view** of both databases (production + temporary).
2. If `db` is provided **and** `hosts` and `paths` are empty:
   - Open the production database read-only, build the report directly.
3. If `db` is `None`:
   - Current behaviour (temporary database only) unchanged.

The merge is done at the `StoredCert` level: we collect `StoredCert` objects from both inventories, **deduplicate by SHA-256 fingerprint** (merging observations from both sources), then pass the combined list to `explain()` to build the report. This preserves cross-inventory issuer matching (e.g., leaf in temp DB with issuer only in prod DB) and ensures the same certificate is not double-counted when it exists in both databases (common case: scheduled `collect` then ad-hoc `check --path`).

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| Open production DB with SQLite `readonly=true` URI and skip `ingest` | SQLite read-only URI still allows `PRAGMA` and schema creation; `Inventory.__init__` runs `executescript(_SCHEMA)` which would fail. Changing `Inventory` to support read-only opens a larger refactor. |
| Copy production DB to temp, ingest into copy, use copy | Extra I/O and disk usage; the production DB can be large. Merging in memory is simpler and faster. |
| Add `--read-only` flag to `check` | The CLI already promises read-only semantics for `--db`; adding a flag admits the current behaviour is wrong. |
| Make `Inventory.ingest` a no-op when a `read_only` flag is set | Requires threading the flag through `CollectionResult`, `Inventory`, and all callers (`scan`, `collect`, `import`). Scope creep. |

The chosen approach (merge in memory, temp DB for ad-hoc data) touches only `check.py`, keeps `Inventory` unchanged, and matches the existing temp-DB pattern.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Memory pressure if production DB has many certificates | Certificates are already loaded into memory by `Inventory.certificates()` for report building. No additional memory beyond the second list. |
| `Report` merge misses gaps/warnings from one side | `build_report` computes gaps/warnings from the `Inventory` passed to it. We must ensure both inventories' gaps/warnings are preserved. Solution: collect gaps/warnings from both inventories and pass combined lists to `Report`. |
| Existing tests break | Update `test_check_against_existing_db_with_markdown` to verify the production DB file is unchanged after the call (compare file size/hash before/after). Add a new test for `--db` + `--host`. |

## Acceptance Criteria

1. `certclock check --db prod.db` (no `--host`/`--path`) exits 0/1/2 based on `prod.db` contents; `prod.db` mtime and size unchanged.
2. `certclock check --db prod.db --host example.test:443` evaluates the union of `prod.db` certificates and the live TLS fetch; `prod.db` mtime and size unchanged.
3. `certclock check --db prod.db --path /etc/ssl/cert.pem` evaluates the union; `prod.db` unchanged.
4. `certclock check --host example.test:443` (no `--db`) works as before (temp DB only).
5. All existing `pytest -q` tests pass.
6. No changes to `Inventory`, `collectors`, `config`, or other commands.

---

## Detailed Implementation Plan

### Target Scope & File Boundary

**Modified file:** `src/certclock/check.py` only.

**Functions to modify:**
- `run_check` (lines 63–100)
- Helper: new `_deduplicate_certs` to merge observations by fingerprint
- Helper: `_build_merged_report` to build report from deduplicated certs via `explain()`

**No other files changed.**

### Actionable Steps

#### 1. Refactor `run_check` to separate the "production DB" path from the "ad-hoc collection" path

```python
def run_check(
    *,
    db: str | None,
    hosts: list[str],
    paths: list[str],
    owners: str | None = None,
    warn_days: int = 30,
    crit_days: int = 7,
    max_validity_days: int = 100,
    timeout: float = 8.0,
    fail_on: str = "crit",
) -> CheckOutcome:
    # Validation unchanged
    if not db and not hosts and not paths:
        raise ValueError("pass --db, or at least one --host or --path")
    if crit_days > warn_days:
        raise ValueError("--crit-days must not be larger than --warn-days")

    config = Config(
        database=db or "",
        owners_file=owners,
        horizon_days=max(90, warn_days),
        warn_days=warn_days,
        crit_days=crit_days,
        notify_within_days=warn_days,
        weak_rsa_bits=2048,
        max_validity_days=max_validity_days,
    )
    config._base_dir = Path.cwd()
    now = utcnow()

    # Case A: db provided, no ad-hoc collection -> read prod DB only
    if db and not hosts and not paths:
        with Inventory(db) as inventory:
            report = build_report(inventory, config, now)
        return evaluate(report, fail_on)

    # Case B: db provided AND ad-hoc collection -> merge prod + temp
    if db and (hosts or paths):
        with Inventory(db) as prod_inventory:
            prod_certs = prod_inventory.certificates()
            prod_gaps = prod_inventory.gaps()
            prod_warnings = prod_inventory.warnings()

        with tempfile.TemporaryDirectory(prefix="certclock-check-") as scratch:
            temp_db = str(Path(scratch) / "check.db")
            with Inventory(temp_db) as temp_inventory:
                if hosts:
                    endpoints = parse_hosts("\n".join(hosts))
                    temp_inventory.ingest(TlsCollector(endpoints, timeout=timeout).collect(), now)
                if paths:
                    temp_inventory.ingest(FileCollector(paths).collect(), now)
                temp_certs = temp_inventory.certificates()
                temp_gaps = temp_inventory.gaps()
                temp_warnings = temp_inventory.warnings()

        # Merge certificates, gaps, warnings
        # Deduplicate by SHA-256 fingerprint and merge observations
        all_certs = _deduplicate_certs(prod_certs + temp_certs)
        all_gaps = prod_gaps + temp_gaps
        all_warnings = prod_warnings + temp_warnings

        # Build merged report via explain() on deduplicated certs (preserves cross-DB issuer matching)
        report = _build_merged_report(
            all_certs, all_gaps, all_warnings, config, now
        )
        return evaluate(report, fail_on)

    # Case C: no db -> current behaviour (temp DB only)
    with tempfile.TemporaryDirectory(prefix="certclock-check-") as scratch:
        database = str(Path(scratch) / "check.db")
        with Inventory(database) as inventory:
            if hosts:
                endpoints = parse_hosts("\n".join(hosts))
                inventory.ingest(TlsCollector(endpoints, timeout=timeout).collect(), now)
            if paths:
                inventory.ingest(FileCollector(paths).collect(), now)
            report = build_report(inventory, config, now)
    return evaluate(report, fail_on)
```

#### 2. Import `Report` from `certclock.models` (already imported at line 29)

#### 3. Remove the `config.database = db or ""` assignment for Cases B and C since we don't pass a DB path to `build_report` in those branches. The `Config` object is only used for thresholds; `database` field is unused by `build_report` when we construct `Report` directly.

### Error Behaviour

- Invalid `--host`/`--path` syntax: existing `ValueError` from `parse_hosts` / `FileCollector` propagates, caught in `_cmd_check` → exit 3.
- Unreadable `--db` file: `Inventory.__init__` raises `OSError` → caught in `_cmd_check` → exit 3.
- `crit_days > warn_days`: existing validation → exit 3.
- No `--db`, `--host`, or `--path`: existing validation → exit 3.

All error paths unchanged.

### Test Cases (pytest)

**New tests in `tests/test_check.py`:**

```python
def test_check_db_read_only_no_host_path(tmp_path: Path, capsys):
    """--db alone reads production DB and never writes to it."""
    # Create a production DB with one certificate
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0
    prod_size = prod_db.stat().st_size
    prod_mtime = prod_db.stat().st_mtime

    # Run check --db only
    assert main(["check", "--db", str(prod_db)]) == EXIT_OK

    # DB unchanged
    assert prod_db.stat().st_size == prod_size
    assert prod_db.stat().st_mtime == prod_mtime


def test_check_db_with_host_does_not_write_prod_db(tmp_path: Path, capsys):
    """--db with --host merges in memory; production DB untouched."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0
    prod_size = prod_db.stat().st_size
    prod_mtime = prod_db.stat().st_mtime

    now = utcnow()
    minted = mint("edge.example.test", not_before=now - dt.timedelta(days=1), not_after=now + dt.timedelta(days=3))
    with LocalTlsServer(minted.pem, minted.key_pem) as server:
        code = main(["check", "--db", str(prod_db), "--host", f"127.0.0.1:{server.port} edge.example.test", "--timeout", "5"])
    assert code == EXIT_CRIT  # edge cert is within 7 days

    # Production DB unchanged
    assert prod_db.stat().st_size == prod_size
    assert prod_db.stat().st_mtime == prod_mtime


def test_check_db_with_path_does_not_write_prod_db(tmp_path: Path, capsys):
    """--db with --path merges in memory; production DB untouched."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0
    prod_size = prod_db.stat().st_size

    _cert_file(tmp_path, "soon.example.test", 20)
    assert main(["check", "--db", str(prod_db), "--path", str(tmp_path / "soon.example.test.pem"), "--fail-on", "warn"]) == EXIT_WARN

    assert prod_db.stat().st_size == prod_size


def test_check_db_merge_preserves_both_gaps_and_warnings(tmp_path: Path):
    """Gaps and warnings from both prod and temp DB appear in report."""
    prod_db = tmp_path / "prod.db"
    _cert_file(tmp_path, "prod.example.test", 200)
    assert main(["collect", "files", "--db", str(prod_db), "--path", str(tmp_path / "prod.example.test.pem")]) == 0

    # Corrupt a file to create a gap in temp collection
    bad_pem = tmp_path / "bad.pem"
    bad_pem.write_text("not a certificate", encoding="utf-8")

    from certclock.check import run_check
    outcome = run_check(db=str(prod_db), hosts=[], paths=[str(bad_pem)], fail_on="never")
    report = outcome.report

    # Prod cert present
    assert any(c.subject_cn == "prod.example.test" for c in report.certificates)
    # Gap from bad file present
    assert any(g.source == "file" and "bad.pem" in g.detail for g in report.gaps)


def test_check_without_db_still_uses_temp_db(tmp_path: Path, capsys):
    """No --db: current behaviour unchanged (temp DB only)."""
    _cert_file(tmp_path, "far.example.test", 200)
    assert main(["check", "--path", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("OK: 1 certificates")
```

**Existing test to update:**
- `test_check_against_existing_db_with_markdown`: add assertion that the demo DB file size/mtime is unchanged after the `check` call.

### Documentation Changes

- **README.md**: No change needed — the documented behaviour already matches the fix.
- **CHANGELOG.md** (if exists): Add a one-line entry under `## Fixed`:
  > `check --db` with `--host`/`--path` no longer writes to the production database; ad-hoc data is merged in memory from a temporary database.
- No other docs affected.

### Verification Checklist

- [ ] `pytest -q` passes (all existing + new tests)
- [ ] `ruff check .` passes
- [ ] Manual smoke test:
  ```bash
  certclock demo --offline --out /tmp/demo
  certclock check --db /tmp/demo/certclock.db --host 127.0.0.1:9999  # port closed, gap only
  # Verify /tmp/demo/certclock.db size unchanged
  ```
- [ ] No import errors, no runtime errors in the three code paths (A, B, C)