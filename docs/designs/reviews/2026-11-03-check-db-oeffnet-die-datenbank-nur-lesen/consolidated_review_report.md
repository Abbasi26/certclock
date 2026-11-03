# Consolidated Review Report

**Target:** `docs/designs/2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md` (full document)
**Source Reviews:** 5 stages (Zoom Out ×2, Comprehension, Critic, Implementation Readiness)
**Date:** 2026-11-03

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Blocker | 3 |
| 🟡 Major | 17 |
| 🟢 Nit | 17 |
| **Total Tasks** | **37** |
| Contested (not tasks) | 9 |

---

## Consolidated Tasks (Deduplicated)

### 🔴 Blocker

#### T-01: Type mismatch — `Report` constructed from `StoredCert` bypassing `explain()`
**Status:** `fixed` (design must call `explain()` on merged+deduped `StoredCert` list)
**Sources:** ZO-01, CR-01, CD-01, IR-01
**Details:** Case B does `prod_certs = prod_inventory.certificates()` → `list[StoredCert]`, concatenates, passes to `Report(certificates=all_certs)`. `Report.certificates` expects `list[ReportCert]`. `StoredCert` lacks `days_remaining`, `bucket`, `problems`, `sources`, `owner`, `service`, `dependency_note`. Every consumer (`evaluate`, `render_text`, `render_json_outcome`, `Report.summary()`) crashes with `AttributeError`. Fix: merge `StoredCert` lists, dedupe by fingerprint, call `explain(merged, now, owners=assign_owners(...), weak_rsa_bits=..., max_validity_days=...)`, pass resulting `ReportCert` list to `Report`.

#### T-02: Owner rules silently ignored in Case B
**Status:** `fixed` (resolved by T-01 fix — `explain()` call includes `assign_owners()`)
**Sources:** ZO-02, CR-03, IR-04
**Details:** `build_report` loads owners via `config.resolve(config.owners_file)` and calls `assign_owners(stored, rules)` before `explain()`. Case B constructs `Report` directly, never calling `load_owners`/`assign_owners`. `check --db prod.db --host … --owners owners.yml` produces unowned report — behaviour regression vs. single-DB path.

#### T-03: Acceptance criteria require unchanged production DB but design provides no read-only mechanism
**Status:** `accepted risk` (design chooses "open normally, never call `ingest`" as enforceable convention)
**Sources:** CO-01, ST-06
**Details:** Acceptance criteria 1–3 assert production DB `mtime`/`size` unchanged. Cases A and B open DB via `Inventory(db)` which runs `executescript(_SCHEMA)` (idempotent today). No read-only URI (rejected in Alternatives because `Inventory.__init__` would fail). The "no writes" guarantee rests on restraint (never calling `ingest`), not a mechanical read-only handle. This is documented as the chosen approach; future `Inventory` changes could break it — tracked as accepted risk.

---

### 🟡 Major

#### T-04: No fingerprint deduplication across inventories
**Status:** `fixed` (design must dedupe by SHA-256 fingerprint before `explain()`)
**Sources:** ZO-03, CR-02, IR-02
**Details:** `all_certs = prod_certs + temp_certs` can contain same fingerprint twice (e.g., `collect` then `check --path` same file). `Inventory` dedupes within one DB (PK on fingerprint) but not across two. `Report.summary()` double-counts; certs double-flagged. Fix: dedupe merged `StoredCert` list by `fingerprint` before `explain()`.

#### T-05: Cross-inventory dependency analysis lost
**Status:** `fixed` (resolved by T-01 fix — single `explain()` on combined list)
**Sources:** ZO-04
**Details:** `explain()` indexes all certs together for issuer matching (`_choose_issuer`, `_chain_includes_issuer`). If fixed by calling `explain()` per-inventory and concatenating `ReportCert` rows, a leaf in temp DB whose issuer lives only in prod DB would be wrongly flagged `issuer_not_in_inventory` and lose `issuer_expires_first`. Correct merge: single `explain()` on combined `StoredCert` list.

#### T-06: `weak_rsa_bits` / `max_validity_days` thresholds unused in Case B
**Status:** `fixed` (resolved by T-01 fix — `explain()` receives these params)
**Sources:** CR-04
**Details:** `Config` built with `weak_rsa_bits=2048`, `max_validity_days=...` but Case B bypasses `build_report` which is the only code passing these to `explain()`. In Case B, `weak_key` and `long_validity` findings never produced.

#### T-07: Architecture weakens requirement with "read-only (or open normally)" parenthetical
**Status:** `fixed` (architecture must state "open normally, never call `ingest`" as primary)
**Sources:** CO-02, ST-03, ST-07, CR-08, ST-01 (part), ST-02 (part), ST-03 (part)
**Details:** Line 27: "Open the production database read-only (or open normally but do not call `ingest` on it)." Read-only branch explicitly rejected in Alternatives (line 42) because `Inventory.__init__` runs `executescript(_SCHEMA)`. Parenthetical buries the actual viable path. Architecture must lead with chosen approach; rejected option belongs in Alternatives only.

#### T-08: Promised re-sorting not performed in Case B merge
**Status:** `fixed` (design must sort merged `StoredCert` list before `explain()`, or note renderers sort)
**Sources:** CO-03
**Details:** Architecture (line 36) says merge is "list concatenation followed by re-sorting." Case B implementation (line 142) does `all_certs = prod_certs + temp_certs` with no sort. Report order differs from single-inventory paths (Case A, Case C), producing inconsistent output.

#### T-09: Mis-scoped statement about which branches bypass `build_report`
**Status:** `fixed` (Step 3 text must match code: only Case B bypasses `build_report`)
**Sources:** CO-04, IR-03, CR-05
**Details:** Line 174 claims `database` field unused "for Cases B and C since we don't pass a DB path to `build_report` in those branches." But Case C (lines 160–169) **does** call `build_report`, as does Case A. Only Case B bypasses it. Statement is wrong for 2 of 3 cases.

#### T-10: `CheckOutcome` and test helpers undefined in document
**Status:** `fixed` (remove non-compilable test code from design doc per Standard §3, or add type refs)
**Sources:** CO-05
**Details:** Return type `CheckOutcome` used in signature and `.report` dereferenced in test (line 262), but never defined. Exit-code constants (`EXIT_OK`, `EXIT_CRIT`, `EXIT_WARN`), fixtures (`_cert_file`, `mint`, `LocalTlsServer`, `utcnow`, `dt`, `Gap`) also undefined. Test snippet not self-contained; merge type compatibility (`list[Gap]` vs `Report.gaps`) unverifiable from doc alone.

#### T-11: Risks table incomplete — missing concurrency and read-write handle failure modes
**Status:** `fixed` (add rows for concurrent writer lock and future `Inventory` write risk)
**Sources:** ST-01
**Details:** Standard requires explicit failure modes for central promise ("no writes to production DB"). Not addressed: (1) Production DB opened read-write — "no writes" guarantee rests on restraint, not read-only handle; `Inventory.__init__` runs `executescript(_SCHEMA)` — foot-gun for future changes. (2) Concurrency/locking: concurrent writer can cause `sqlite3.OperationalError: database is locked` → exit 3 or stall; no `busy_timeout` in plan. Acceptance criteria assert behavioural check, not mechanical guarantee.

#### T-12: Redundant "never write back" phrasing
**Status:** `fixed` (state once in Architecture where mechanism defined)
**Sources:** ST-08
**Details:** Constraint stated three times (lines 12, 30, 36) with no additional information. Goals should state *what*; Architecture states *how*.

#### T-13: "Merge" overloaded for two different operations
**Status:** `fixed` (use "combine" or "unify" for gaps/warnings)
**Sources:** ST-09
**Details:** Line 30: "merged view"; line 36: merge = "list concatenation followed by re-sorting"; line 54: "merge" for combining gaps/warnings. Word carries two different operations without distinction.

#### T-14: "can therefore corrupt" — uncalibrated causal claim
**Status:** `fixed` (remove "therefore"; relocate consequence to Risks as measured statement)
**Sources:** ST-10
**Details:** Line 7: "A one-off `check` run **can therefore corrupt** the production snapshot..." "Therefore" is filler; "can corrupt" is speculative hedging. Assumes cron job's snapshot is production DB (not stated). Change to: "A one-off `check` run may overwrite observations in the production DB that a scheduled scan relies on."

#### T-15: "documents that" wordy
**Status:** `fixed` (change to "states that")
**Sources:** ST-11
**Details:** Line 5: "The `certclock check` command **documents that** `--db` reads..." — "states that" is direct.

#### T-16: "Certificates are already loaded" asserts implementation detail
**Status:** `fixed` (calibrate to "`Inventory.certificates()` loads certificates into memory")
**Sources:** ST-04 (Stage 9 egm-style)
**Details:** Line 53: "Certificates **are already loaded into memory** by `Inventory.certificates()`..." asserts implementation detail as fact. Calibrate to state behaviour, not implementation assumption.

#### T-17: Test comment "edge cert is within 7 days" should reference `crit_days` config
**Status:** `fixed` (tie comment to configurable threshold)
**Sources:** ST-05 (Stage 9 egm-style)
**Details:** Test comment asserts expectation as fact without tying to threshold config. Test uses `--fail-on crit` with default `crit_days=7`. Comment should reference config: "# edge cert expires within `crit_days` (default 7)".

#### T-18: Smoke test verification "size unchanged" not concrete
**Status:** `fixed` (specify `stat -c%s` before/after)
**Sources:** ST-06 (Stage 9 egm-style)
**Details:** Smoke test step asserts verification but doesn't state how. "Verify size unchanged" is an instruction, not a verification method. Must specify concrete command.

#### T-19: SQLite read-only URI claim imprecise in Alternatives
**Status:** `fixed` (correction: `Inventory.__init__` runs `executescript(_SCHEMA)` which fails on read-only)
**Sources:** ST-05 (Stage 7 egm-structural), ST-03 (part)
**Details:** Line 42: "SQLite read-only URI still allows `PRAGMA` and schema creation." A `mode=ro` URI cannot create schema; actual blocker is `Inventory.__init__` calling `executescript(_SCHEMA)` (inventory.py:82) which fails on read-only connection.

#### T-20: CLI help line 86 citation overreaches
**Status:** `fixed` (cite `check.py` docstring lines 10–12 only)
**Sources:** ST-02 (Stage 7 egm-structural)
**Details:** Line 5 cites "CLI help line 86" as evidence for "throwaway database" claim. Verified: `cli.py:86` is `help="read an existing inventory"` — only states read path. Throwaway wording comes solely from `check.py` docstring.

---

### 🟢 Nit

#### T-21: Implementation plan violates Anti-Weeds (Standard §3) — premature code detail
**Status:** `fixed` (reduce to high-level steps referencing Architecture; move code to implementation PR)
**Sources:** ZO-05
**Details:** "Detailed Implementation Plan" (lines 84–170) contains full refactored `run_check` source, five inline pytest functions, per-step commentary. High-level sections must focus on architecture/interfaces/data flows. Code listing became spec — where errors survived review.

#### T-22: Step 3 text contradicts code block ("assignment" vs constructor argument)
**Status:** `fixed` (update text: "`Config` constructor receives `database=db or ""` but field unused in Case B")
**Sources:** ZO-06, CR-05, IR-05
**Details:** Line 174: "Remove the `config.database = db or ""` assignment for Cases B and C" — but code block (lines 103–112) passes `database=db or ""` to `Config(...)` constructor; no separate assignment exists.

#### T-23: Nonexistent `--db` path creates empty SQLite file
**Status:** `fixed` (add guard `Path(db).exists()` or acceptance criterion for error on missing DB)
**Sources:** ZO-07
**Details:** Case B: `with Inventory(db) as prod_inventory` calls `sqlite3.connect()` + `executescript(_SCHEMA)`, creating file if missing. `check --db /new/prod.db --host …` writes empty `prod.db`. Acceptance criteria 1–3 only assert mtime/size unchanged for *existing* DB.

#### T-24: Promised test update not present (`test_check_against_existing_db_with_markdown`)
**Status:** `fixed` (add `stat()` before/after assertions as described)
**Sources:** ZO-08, IR-06, CD-09
**Details:** Plan (line 279) says "add assertion that demo DB file size/mtime unchanged after `check` call." Current test (`test_check.py:89–97`) only checks Markdown output. This is the only acceptance evidence for criteria 1–3.

#### T-25: Memory mitigation understated
**Status:** `fixed` (change to "Memory usage doubles during merge (both certificate lists held simultaneously); acceptable for typical inventories")
**Sources:** CO-06, ST-15
**Details:** Line 53: "No additional memory beyond the second list" — Case B holds `prod_certs` AND `temp_certs` simultaneously; entire production list duplicated.

#### T-26: Gap/warning merge types undefined
**Status:** `fixed` (add type references: `Gap` from `certclock.models`, `gaps: list[Gap]`, `warnings: list[str]`)
**Sources:** CO-07
**Details:** Risk table and implementation concatenate `Inventory.gaps()`/`warnings()` into `Report` fields, but return types and `Gap`/`Report` field types never defined in doc.

#### T-27: Private attribute `_base_dir` set without explanation
**Status:** `fixed` (add comment: `# ensures temp DB scratch directory resolves relative to cwd` or remove if unused)
**Sources:** CO-08
**Details:** Line 113: `config._base_dir = Path.cwd()` sets private attribute with no stated purpose.

#### T-28: Test snippet relies on out-of-scope helpers
**Status:** `fixed` (remove test code from design doc per Standard §3, or add import comments)
**Sources:** CO-09
**Details:** Pytest examples use `_cert_file`, `mint`, `LocalTlsServer`, `utcnow`, `dt`, `EXIT_*` constants without defining/importing them.

#### T-29: New failure modes in Case B unaddressed
**Status:** `fixed` (add `OSError` from `TemporaryDirectory` and second `Inventory` to error mapping)
**Sources:** CO-10
**Details:** Error-behaviour section claims all error paths unchanged, but Case B introduces second `Inventory` open and `TemporaryDirectory` whose failures (e.g., temp dir creation failing after prod DB opened) not covered by `OSError` → exit 3 mapping.

#### T-30: CHANGELOG convention mismatch (`## Fixed` vs `## Unreleased`)
**Status:** `fixed` (change to "Add entry under `## Unreleased`")
**Sources:** CR-06
**Details:** Line 284 says add entry "under `## Fixed`". Real `CHANGELOG.md` has no `## Fixed` section; convention is `## Unreleased` (`CHANGELOG.md:3`).

#### T-31: Error Behaviour misstates exception type (`sqlite3.OperationalError` not `OSError`)
**Status:** `fixed` (correct to `sqlite3.OperationalError`; verify `_cmd_check` catch clause)
**Sources:** CR-07
**Details:** Line 190 claims unreadable `--db` raises `OSError`. Actually `sqlite3.connect` raises `sqlite3.OperationalError` (subclass of `Exception`, not `OSError`); `_cmd_check` catches `(OSError, ValueError, RuntimeError)` — unhandled traceback would result.

#### T-32: "throwaway" vs "temporary" database inconsistency
**Status:** `fixed` (use "temporary database" consistently)
**Sources:** ST-12
**Details:** Line 5 uses "throwaway database"; lines 13 and 34 use "temporary database." Architecture (line 28) uses "temporary database."

#### T-33: "temp DB" / "scratch directory" / "temporary database" inconsistency
**Status:** `fixed` (use "scratch directory" for directory, "temporary database" for DB inside; avoid "temp DB")
**Sources:** ST-13
**Details:** Line 24: "temporary directory"; line 28: "temporary database"; line 43: "temp DB"; line 47: "temp DB." Scratch location is a directory; database lives inside it.

#### T-34: "from one side" vague in Risks table
**Status:** `fixed` (change to "from either inventory")
**Sources:** ST-16
**Details:** Line 54: "Report merge misses gaps/warnings from one side." "From either inventory" is precise.

#### T-35: Jargon "touches only" → "modifies only"
**Status:** `fixed` (replace colloquialism)
**Sources:** ST-08 (Stage 9 egm-style)
**Details:** Line 47: "touches only `check.py`" — "modifies only" is standard.

#### T-36: Synonym redundancy "replaces"/"deleting"
**Status:** `fixed` (pick one: "overwrites" or "deletes")
**Sources:** ST-09 (Stage 9 egm-style)
**Details:** Line 6: "replaces the `tls`/`tls-chain` or `file` sources..., potentially deleting legitimate observations." Near-synonyms in context.

#### T-37: Subjective "simpler and faster" → "avoids extra I/O and disk usage"
**Status:** `fixed` (replace subjective claim with measurable statement)
**Sources:** ST-10 (Stage 9 egm-style)
**Details:** Line 47: "...**simpler and faster**." No measurements provided.

---

## Traceability Matrix

| Raw Finding | Reviewer | Stage | Consolidated Task | Status |
|-------------|----------|-------|-------------------|--------|
| ZO-01 | egm-zoom-out | 5 | T-01 | fixed |
| ZO-02 | egm-zoom-out | 5 | T-02 | fixed |
| ZO-03 | egm-zoom-out | 5 | T-04 | fixed |
| ZO-04 | egm-zoom-out | 5 | T-05 | fixed |
| ZO-05 | egm-zoom-out | 5 | T-21 | fixed |
| ZO-06 | egm-zoom-out | 5 | T-22 | fixed |
| ZO-07 | egm-zoom-out | 5 | T-23 | fixed |
| ZO-08 | egm-zoom-out | 5 | T-24 | fixed |
| CO-01 | egm-comprehension | 6 | T-03 | accepted risk |
| CO-02 | egm-comprehension | 6 | T-07 | fixed |
| CO-03 | egm-comprehension | 6 | T-08 | fixed |
| CO-04 | egm-comprehension | 6 | T-09 | fixed |
| CO-05 | egm-comprehension | 6 | T-10 | fixed |
| CO-06 | egm-comprehension | 6 | T-25 | fixed |
| CO-07 | egm-comprehension | 6 | T-26 | fixed |
| CO-08 | egm-comprehension | 6 | T-27 | fixed |
| CO-09 | egm-comprehension | 6 | T-28 | fixed |
| CO-10 | egm-comprehension | 6 | T-29 | fixed |
| CR-01 | egm-design | 7 | T-01 | fixed |
| CR-02 | egm-design | 7 | T-04 | fixed |
| CR-03 | egm-design | 7 | T-02 | fixed |
| CR-04 | egm-design | 7 | T-06 | fixed |
| CR-05 | egm-design | 7 | T-09 | fixed |
| CR-06 | egm-design | 7 | T-30 | fixed |
| CR-07 | egm-design | 7 | T-31 | fixed |
| CR-08 | egm-design | 7 | T-07 | fixed |
| ST-01 | egm-structural | 7 | T-11 | fixed |
| ST-02 | egm-structural | 7 | T-20 | fixed |
| ST-03 | egm-structural | 7 | T-07 | fixed |
| ST-04 | egm-structural | 7 | T-08 | fixed |
| ST-05 | egm-structural | 7 | T-19 | fixed |
| ST-06 | egm-style | 7 | T-03 | accepted risk |
| ST-07 | egm-style | 7 | T-07 | fixed |
| ST-08 | egm-style | 7 | T-12 | fixed |
| ST-09 | egm-style | 7 | T-13 | fixed |
| ST-10 | egm-style | 7 | T-14 | fixed |
| ST-11 | egm-style | 7 | T-15 | fixed |
| ST-12 | egm-style | 7 | T-32 | fixed |
| ST-13 | egm-style | 7 | T-33 | fixed |
| ST-14 | egm-style | 7 | T-07 | fixed |
| ST-15 | egm-style | 7 | T-25 | fixed |
| ST-16 | egm-style | 7 | T-34 | fixed |
| ZO-01..08 (dup) | egm-zoom-out | 8 | (duplicates) | — |
| IR-01 | egm-impl-readiness | 9 | T-01 | fixed |
| IR-02 | egm-impl-readiness | 9 | T-04 | fixed |
| IR-03 | egm-impl-readiness | 9 | T-09 | fixed |
| IR-04 | egm-impl-readiness | 9 | T-02 | fixed |
| IR-05 | egm-impl-readiness | 9 | T-22 | fixed |
| IR-06 | egm-impl-readiness | 9 | T-24 | fixed |
| CD-01 | egm-codebase-details | 9 | T-01 | fixed |
| CD-02 | egm-codebase-details | 9 | (contested) | contested |
| CD-03 | egm-codebase-details | 9 | (contested) | contested |
| CD-04 | egm-codebase-details | 9 | (contested) | contested |
| CD-05 | egm-codebase-details | 9 | T-09 | fixed |
| CD-06 | egm-codebase-details | 9 | (contested) | contested |
| CD-07 | egm-codebase-details | 9 | (contested) | contested |
| CD-08 | egm-codebase-details | 9 | (contested) | contested |
| CD-09 | egm-codebase-details | 9 | T-24 | fixed |
| CD-10 | egm-codebase-details | 9 | (contested) | contested |
| CD-11 | egm-codebase-details | 9 | (contested) | contested |
| CD-12 | egm-codebase-details | 9 | (contested) | contested |
| ST-01..03 (dup) | egm-style | 9 | T-07, T-19 | fixed |
| ST-04 | egm-style | 9 | T-16 | fixed |
| ST-05 | egm-style | 9 | T-17 | fixed |
| ST-06 | egm-style | 9 | T-18 | fixed |
| ST-07 (dup) | egm-style | 9 | T-14, T-32 | fixed |
| ST-08 | egm-style | 9 | T-35 | fixed |
| ST-09 | egm-style | 9 | T-36 | fixed |
| ST-10 | egm-style | 9 | T-37 | fixed |

---

## Contested Findings (Not Tasks)

| ID | Reviewer | Stage | Reason |
|----|----------|-------|--------|
| CD-02 | egm-codebase-details | 9 | Clarification: gaps/warnings types compatible; not a defect |
| CD-03 | egm-codebase-details | 9 | Verified: `tempfile`/`Path` imports already present in `check.py:18-20` |
| CD-04 | egm-codebase-details | 9 | Verified: `Gap` used as runtime value, not type annotation; no code change needed |
| CD-06 | egm-codebase-details | 9 | Verified: `EXIT_ERROR=3` caught correctly in `_cmd_check` |
| CD-07 | egm-codebase-details | 9 | Verified: `_cert_file` helper in same test file |
| CD-08 | egm-codebase-details | 9 | Verified: `mint`/`LocalTlsServer` imported in test file |
| CD-10 | egm-codebase-details | 9 | Subjective: README "no change needed" — not a design defect |
| CD-11 | egm-codebase-details | 9 | Verified: CHANGELOG exists with `## Unreleased` |
| CD-12 | egm-codebase-details | 9 | Verified: smoke test path and port expectation correct |

---

## Reviewer Coverage

| Reviewer | Stage | Status |
|----------|-------|--------|
| egm-zoom-out | 5 (Initial Zoom Out) | ✅ Completed |
| egm-comprehension | 6 (Comprehension) | ✅ Completed |
| egm-design | 7 (Critic) | ✅ Completed |
| egm-structural | 7 (Critic) | ✅ Completed |
| egm-style | 7 (Critic) | ✅ Completed |
| egm-zoom-out | 8 (Intermediate Zoom Out) | ✅ Completed |
| egm-implementation-readiness | 9 (Impl Readiness) | ✅ Completed |
| egm-codebase-details | 9 (Impl Readiness) | ✅ Completed |
| egm-style | 9 (Impl Readiness) | ✅ Completed |

**NOT RUN:** None — all 9 review processes executed.

---

OPEN-BLOCKERS: 0