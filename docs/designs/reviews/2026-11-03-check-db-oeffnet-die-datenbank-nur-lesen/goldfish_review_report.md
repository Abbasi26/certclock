# Goldfish Annotated Review Report

**Target:** `docs/designs/2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md` (Feature section, lines 1–67)

## Prioritized Findings & AI Suggestions

### ZO-01 [egm-zoom-out] - Severity: Blocker
*   **Affected Scope:** Lines 147–156 (Case B `Report` construction)
*   **Discrepancy:** Merged `Report` is constructed from `StoredCert` objects and skips `explain()` entirely. `Inventory.certificates()` returns `list[StoredCert]`, but `Report.certificates` expects `list[ReportCert]`. Every consumer (`evaluate`, `render_text`, `render_json_outcome`) crashes with `AttributeError` on missing fields (`days_remaining`, `sources`, `problems`, `bucket`, etc.).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The design's Case B implementation is fundamentally broken. It must merge `StoredCert` lists, dedupe by fingerprint, call `explain()` with `assign_owners()`, then pass resulting `ReportCert` list to `Report` constructor.
*   ***Proposed Edit:***
    *   Location: Lines 141–157 (Case B merge logic)
    *   Change: Replace direct `Report(certificates=all_certs, ...)` with deduplicated `StoredCert` merge → `explain(merged_stored, now, ..., owners=assign_owners(merged_stored, rules))` → `Report(certificates=report_certs, ...)`

---

### ZO-02 [egm-zoom-out] - Severity: Blocker
*   **Affected Scope:** Lines 147, 174 (Owner rules in Case B)
*   **Discrepancy:** Owner rules are never applied in Case B. `build_report` loads owners file and calls `assign_owners()`, but Case B constructs `Report` directly, bypassing this. `check --db prod.db --host … --owners owners.yml` would silently produce unowned reports.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Direct consequence of bypassing `build_report`. The fix in ZO-01 (calling `explain()` with owners) resolves this.
*   ***Proposed Edit:***
    *   Location: Lines 141–157 (Case B)
    *   Change: Ensure `assign_owners(merged_stored, rules)` is called and passed to `explain()` as part of ZO-01 fix.

---

### ZO-03 [egm-zoom-out] - Severity: Major
*   **Affected Scope:** Lines 142–144 (Certificate merge)
*   **Discrepancy:** No deduplication of certificates across the two inventories. `all_certs = prod_certs + temp_certs` can contain the same fingerprint twice, causing double-counting in `summary()` and duplicate listings.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The design promises "union" (line 60) but implements bare concatenation. Must dedupe by SHA-256 fingerprint before `explain()`.
*   ***Proposed Edit:***
    *   Location: Line 142
    *   Change: Replace `all_certs = prod_certs + temp_certs` with deduplication logic (e.g., `{c.fingerprint: c for c in prod_certs + temp_certs}.values()`).

---

### ZO-04 [egm-zoom-out] - Severity: Major
*   **Affected Scope:** Lines 146–157 (Cross-inventory dependency analysis)
*   **Discrepancy:** Cross-inventory dependency analysis is lost. If `explain()` were called per-inventory and results concatenated, a leaf in temp DB whose issuer is only in prod DB would be wrongly flagged `issuer_not_in_inventory`.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Correct merge must feed combined `StoredCert` list into a single `explain()` call — which the ZO-01 fix achieves.
*   ***Proposed Edit:***
    *   Location: Lines 141–157
    *   Change: Single `explain()` call on merged+deduped `StoredCert` list (covered by ZO-01 fix).

---

### ZO-05 [egm-zoom-out] - Severity: Nit
*   **Affected Scope:** Lines 84–170 (Detailed Implementation Plan)
*   **Discrepancy:** Implementation plan violates Standard §3 (Anti-Weeds / Premature Detail). Contains full refactored source listing and inline pytest functions; high-level sections should focus on architecture, interfaces, data flows.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Code-level detail in the plan is where the three errors above survived review. Plan should reference architecture rather than re-derive it in code.
*   ***Proposed Edit:***
    *   Location: Lines 84–170 (entire "Detailed Implementation Plan" section)
    *   Change: Reduce to high-level steps referencing the Proposed Architecture; move code-level details to implementation PR, not design doc.

---

### ZO-06 [egm-zoom-out] - Severity: Nit
*   **Affected Scope:** Line 174 (Step 3 text vs. code block)
*   **Discrepancy:** Plan text says "Remove the `config.database = db or ""` assignment for Cases B and C", but code block at lines 103–112 passes `database=db or ""` directly to `Config(...)` constructor — no separate assignment exists.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Internal inconsistency erodes trust in the listing.
*   ***Proposed Edit:***
    *   Location: Line 174
    *   Change: Update text to match code: "The `Config` constructor receives `database=db or ""` but this field is unused in Cases B and C since we construct `Report` directly."

---

### ZO-07 [egm-zoom-out] - Severity: Nit
*   **Affected Scope:** Unaddressed (Case B edge case)
*   **Discrepancy:** Nonexistent `--db` path leaves an empty SQLite file. `Inventory(db)` calls `sqlite3.connect()` and `executescript(_SCHEMA)`, creating the file even though nothing is ingested.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Acceptance criteria 1–3 only assert mtime/size unchanged for *existing* DB. Need explicit criterion or guard for nonexistent DB.
*   ***Proposed Edit:***
    *   Location: Acceptance Criteria (lines 59–62) or Risks & Mitigations
    *   Change: Add criterion: "If `--db` points to a nonexistent file, `check` exits with error (does not create empty DB)" or add pre-check `Path(db).exists()`.

---

### ZO-08 [egm-zoom-out] - Severity: Nit
*   **Affected Scope:** Line 279 (Test update promise)
*   **Discrepancy:** Plan says "add assertion that demo DB file size/mtime is unchanged" for `test_check_against_existing_db_with_markdown`, but current test only checks Markdown output.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Planned acceptance evidence is currently absent.
*   ***Proposed Edit:***
    *   Location: Line 279
    *   Change: Update the test as described, or note it as a follow-up task in the plan.

---

### CO-01 [egm-comprehension] - Severity: Blocker
*   **Affected Scope:** Lines 117–127 (Cases A/B) vs. lines 59–62 (acceptance criteria)
*   **Discrepancy:** Internal contradiction: acceptance criteria require production DB mtime/size unchanged in all `--db` scenarios, but Cases A and B open production DB via `Inventory(db)` which runs `executescript(_SCHEMA)` — no read-only mechanism proposed.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The design promises no writes but provides no mechanism to enforce it. Must either use read-only URI (with `Inventory` changes, a Non-Goal) or document that "open normally + never call `ingest`" is the enforceable guarantee.
*   ***Proposed Edit:***
    *   Location: Lines 27 (Architecture), 42 (Alternatives), 117–127 (Cases A/B)
    *   Change: Align architecture with chosen approach: "open normally, never call `ingest`" as primary; update Alternatives table to reflect this is the chosen path; remove "read-only" from architecture line 27.

---

### CO-02 [egm-comprehension] - Severity: Major
*   **Affected Scope:** Line 27 (Architecture), implemented at line 124
*   **Discrepancy:** "read-only (or open normally but do not call `ingest`)" parenthetical weakens the requirement. The two are not equivalent (normal open runs schema script).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Parenthetical reads as concession undermining the goal. Architecture should state the actual viable approach as primary.
*   ***Proposed Edit:***
    *   Location: Line 27
    *   Change: "Open the production database normally but do not call `ingest` on it." (Move read-only to Alternatives as rejected option with explanation.)

---

### CO-03 [egm-comprehension] - Severity: Major
*   **Affected Scope:** Line 36 (Architecture) vs. lines 141–156 (Case B implementation)
*   **Discrepancy:** Architecture says merging includes "re-sorting"; Case B concatenates and passes raw list to `Report` with no sort.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Report order will differ from single-inventory paths (Case A, Case C), producing inconsistent output.
*   ***Proposed Edit:***
    *   Location: Line 142 (after dedupe) or line 36
    *   Change: Add sort step (e.g., by `subject_cn` or `fingerprint`) before `explain()`, or update architecture line 36 to match implementation (renderers already sort).

---

### CO-04 [egm-comprehension] - Severity: Major
*   **Affected Scope:** Line 174 vs. lines 117–169
*   **Discrepancy:** Line 174 claims `database` field unused "for Cases B and C since we don't pass a DB path to `build_report` in those branches." But Case C (lines 160–169) **does** call `build_report`, as does Case A. Only Case B bypasses it.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Statement is wrong for two of three cases.
*   ***Proposed Edit:***
    *   Location: Line 174
    *   Change: "Remove the `database` field usage for Case B since we don't pass a DB path to `build_report` in that branch. Cases A and C still use `build_report` and the field is harmless there."

---

### CO-05 [egm-comprehension] - Severity: Major
*   **Affected Scope:** Lines 96, 120, 157, 169 (`CheckOutcome`); lines 200–276 (test helpers)
*   **Discrepancy:** `CheckOutcome` return type used in signature and dereferenced in test, but never defined in document. Exit-code constants and test fixtures (`_cert_file`, `mint`, `LocalTlsServer`, `utcnow`, `dt`, `Gap`) also undefined.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Test snippet is not self-contained; merge's type compatibility (`list[Gap]` vs `Report.gaps`) unverifiable from doc alone.
*   ***Proposed Edit:***
    *   Location: Lines 96, 120, 157, 169, 200–276
    *   Change: Either add type definitions / imports reference, or remove non-compilable test code from design doc (per Standard §3, code listings belong in implementation, not design).

---

### CO-06 [egm-comprehension] - Severity: Nit
*   **Affected Scope:** Line 53 (Risks) vs. lines 125–142 (Case B)
*   **Discrepancy:** Mitigation says "No additional memory beyond the second list," but Case B holds `prod_certs` AND `temp_certs` simultaneously — entire production list duplicated.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Mitigation understates memory usage.
*   ***Proposed Edit:***
    *   Location: Line 53
    *   Change: "Memory usage doubles during merge (both certificate lists held simultaneously); acceptable for typical inventories."

---

### CO-07 [egm-comprehension] - Severity: Nit
*   **Affected Scope:** Lines 54, 142–144, 178–185
*   **Discrepancy:** Gap/warning merge types undefined. `Inventory.gaps()`/`warnings()` return types and `Gap`/`Report` field types not defined in doc.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Type compatibility can only be verified by reading `models.py`.
*   ***Proposed Edit:***
    *   Location: Lines 54, 178–185
    *   Change: Add type references (e.g., `Gap` from `certclock.models`, `gaps: list[Gap]`, `warnings: list[str]`) or remove merge detail from design doc.

---

### CO-08 [egm-comprehension] - Severity: Nit
*   **Affected Scope:** Line 113
*   **Discrepancy:** `config._base_dir = Path.cwd()` sets private attribute with no stated purpose.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Reader cannot determine if it affects temp-DB path resolution or collector behavior.
*   ***Proposed Edit:***
    *   Location: Line 113
    *   Change: Add comment: `# ensures temp DB scratch directory resolves relative to cwd` or remove if unused.

---

### CO-09 [egm-comprehension] - Severity: Nit
*   **Affected Scope:** Lines 200–276 (test snippet)
*   **Discrepancy:** Pytest examples use `_cert_file`, `mint`, `LocalTlsServer`, `utcnow`, `dt`, `EXIT_*` constants without defining/importing them.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Tests as written cannot be evaluated for correctness from document alone.
*   ***Proposed Edit:***
    *   Location: Lines 200–276
    *   Change: Remove test code from design doc (per Standard §3) or add import comments referencing `tests/test_check.py` fixtures.

---

### CO-10 [egm-comprehension] - Severity: Nit
*   **Affected Scope:** Lines 129–157 vs. lines 189–194 (Error Behaviour)
*   **Discrepancy:** Error-behaviour section claims all error paths unchanged, but Case B introduces second `Inventory` open and `TemporaryDirectory` whose failures (e.g., temp dir creation failing after prod DB opened) not covered by `OSError` → exit 3 mapping.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** New failure modes unaddressed.
*   ***Proposed Edit:***
    *   Location: Lines 189–194
    *   Change: Add `OSError` from `TemporaryDirectory` and second `Inventory` to error mapping, or note that `tempfile.TemporaryDirectory` raises `OSError` which is already caught.

---

### CR-01 [egm-design] - Severity: Blocker
*   **Affected Scope:** Lines 36, 123–157 (Case B)
*   **Discrepancy:** Proposed Case B builds `Report` from `StoredCert`, not `ReportCert`. Same as ZO-01.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Duplicate of ZO-01; same fix applies.
*   ***Proposed Edit:*** See ZO-01.

---

### CR-02 [egm-design] - Severity: High
*   **Affected Scope:** Lines 36, 142 (Merge)
*   **Discrepancy:** Merge produces duplicate certificates (no "union" dedup). Same as ZO-03.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Duplicate of ZO-03; same fix applies.
*   ***Proposed Edit:*** See ZO-03.

---

### CR-03 [egm-design] - Severity: Medium
*   **Affected Scope:** Lines 105, 124, 147–156 (`--owners` in Case B)
*   **Discrepancy:** `--owners` accepted and configured but silently ignored in Case B. Same as ZO-02.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Duplicate of ZO-02; same fix applies.
*   ***Proposed Edit:*** See ZO-02.

---

### CR-04 [egm-design] - Severity: Medium
*   **Affected Scope:** Lines 109–111, 147–156 (`weak_rsa_bits` / `max_validity_days`)
*   **Discrepancy:** Config thresholds set but unused in Case B (bypasses `build_report` which passes them to `explain()`).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Root cause same as ZO-01 (bypassing `build_report`/`explain()`). Fix in ZO-01 restores threshold handling.
*   ***Proposed Edit:*** See ZO-01.

---

### CR-05 [egm-design] - Severity: Low
*   **Affected Scope:** Lines 174 vs. 103–112 (Step 3)
*   **Discrepancy:** Step 3 says "Remove the `config.database = db or ""` assignment", but code block passes `Config(database=db or "", ...)` — no post-construction assignment exists.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Duplicate of ZO-06; same fix applies.
*   ***Proposed Edit:*** See ZO-06.

---

### CR-06 [egm-design] - Severity: Low
*   **Affected Scope:** Line 284 (CHANGELOG)
*   **Discrepancy:** Doc says add entry "under `## Fixed`". Real `CHANGELOG.md` has no `## Fixed` section; convention is `## Unreleased`.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Cosmetic but would create incorrect heading.
*   ***Proposed Edit:***
    *   Location: Line 284
    *   Change: "Add a one-line entry under `## Unreleased`."

---

### CR-07 [egm-design] - Severity: Low
*   **Affected Scope:** Line 190 (Error Behaviour)
*   **Discrepancy:** Doc claims unreadable `--db` raises `OSError` → exit 3. Actually `sqlite3.connect` raises `sqlite3.OperationalError` (subclass of `Exception`, not `OSError`); `_cmd_check` catches `(OSError, ValueError, RuntimeError)` — unhandled traceback would result.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Doc asserts incorrect exception type.
*   ***Proposed Edit:***
    *   Location: Line 190
    *   Change: "Unreadable `--db` file: `Inventory.__init__` raises `sqlite3.OperationalError` → caught in `_cmd_check` (which catches `Exception`) → exit 3." (Verify actual catch clause in `cli.py`.)

---

### CR-08 [egm-design] - Severity: Low
*   **Affected Scope:** Lines 36, 124 ("opened read-only")
*   **Discrepancy:** Architecture says "opened read-only" but code opens normally (`Inventory(db)` runs `executescript(_SCHEMA)`). Read-only-ness is by convention (no `ingest` call).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Wording imprecise; Alternatives table correctly explains why true read-only was rejected.
*   ***Proposed Edit:***
    *   Location: Lines 36, 124
    *   Change: "Open the production database normally (do not call `ingest` on it)."

---

### ST-01 [egm-structural] - Severity: Major
*   **Affected Scope:** Lines 49–55 (Risks & Mitigations)
*   **Discrepancy:** Risks table incomplete vs. standard. Does not address: (1) production DB opened read-write — "no writes" guarantee rests on restraint, not read-only handle; `Inventory.__init__` runs `executescript(_SCHEMA)` — foot-gun for future changes. (2) Concurrency/locking unaddressed: concurrent writer can cause `database is locked` → exit 3 or stall; no `busy_timeout` in plan.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Standard requires explicit failure modes and mitigations for central promise ("no writes to production database"). Acceptance criteria assert behavioural check, not mechanical guarantee.
*   ***Proposed Edit:***
    *   Location: Lines 49–55 (Risks table)
    *   Change: Add rows for:
      - Risk: "Production DB opened read-write; future `Inventory` change could write" → Mitigation: "Document 'no ingest' as enforceable convention; consider read-only URI in follow-up."
      - Risk: "Concurrent writer holds SQLite lock → `OperationalError` or stall" → Mitigation: "Set `busy_timeout` on connection; document expected behaviour."

---

### ST-02 [egm-structural] - Severity: Nit
*   **Affected Scope:** Line 5 (Problem Statement)
*   **Discrepancy:** "CLI help line 86" cited as evidence for "throwaway database" claim. Verified: `cli.py:86` is `help="read an existing inventory"` — only states read path. Throwaway wording comes solely from `check.py` docstring.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Citation overreaches; minor accuracy/traceability issue.
*   ***Proposed Edit:***
    *   Location: Line 5
    *   Change: Cite `check.py` docstring lines 10–12 only, or update CLI help to match.

---

### ST-03 [egm-structural] - Severity: Nit
*   **Affected Scope:** Line 27 (Proposed Architecture)
*   **Discrepancy:** Architecture presents rejected option as live guidance: "Open the production database **read-only** (or open normally but do not call `ingest` on it)." Read-only branch explicitly rejected in Alternatives table (line 42) because `Inventory.__init__` runs `executescript(_SCHEMA)`.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Primary architectural statement internally contradictory.
*   ***Proposed Edit:***
    *   Location: Line 27
    *   Change: "Open the production database normally but do not call `ingest` on it." (Matches CO-02/CR-08.)

---

### ST-04 [egm-structural] - Severity: Nit
*   **Affected Scope:** Line 36 (Architecture) vs. implementation plan
*   **Discrepancy:** Architecture says merge is "list concatenation followed by re-sorting"; concrete plan (lines 142–156) does `all_certs = prod_certs + temp_certs` with no re-sort in merge.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** High-level claim and plan disagree.
*   ***Proposed Edit:***
    *   Location: Line 36 or line 142
    *   Change: Align one to the other (see CO-03).

---

### ST-05 [egm-structural] - Severity: Nit
*   **Affected Scope:** Line 42 (Alternatives table)
*   **Discrepancy:** "SQLite read-only URI still allows `PRAGMA` and schema creation." Actually `mode=ro` URI cannot create schema; blocker is `Inventory.__init__` calling `executescript(_SCHEMA)` which fails on read-only connection.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Rejection rationale reaches right conclusion but technical premise is loose.
*   ***Proposed Edit:***
    *   Location: Line 42
    *   Change: "`Inventory.__init__` runs `executescript(_SCHEMA)` (inventory.py:82), which fails on a read-only connection."

---

### ST-06 [egm-style] - Severity: Blocker
*   **Affected Scope:** Lines 59–62 (Acceptance Criteria)
*   **Discrepancy:** Primary goal (line 1) is `--db` opens database **read-only**. Every criterion verifies only `prod.db` *unchanged* (mtime/size). File invariance ≠ read-only opening.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Criteria measure weaker invariant than goal. Must add criterion observing write behaviour (e.g., attempted write denied, or open mode confirmed read-only).
*   ***Proposed Edit:***
    *   Location: Lines 59–62
    *   Change: Add criterion: "Production DB opened in read-only mode (verified via `PRAGMA query_only` or connection URI)" or rephrase goal to match criteria: "never writes to production database."

---

### ST-07 [egm-style] - Severity: Blocker
*   **Affected Scope:** Lines 27 (Architecture) vs. 42 (Alternatives)
*   **Discrepancy:** Architecture proposes read-only opening; Alternatives rejects it. Same as ST-03/CO-02/CR-08.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Duplicate; same fix applies.
*   ***Proposed Edit:*** See ST-03.

---

### ST-08 [egm-style] - Severity: Major
*   **Affected Scope:** Lines 12, 30 (Goals, Architecture)
*   **Discrepancy:** "merge ... in memory ... never write back" / "merged view" stated three times (lines 12, 30, 36) with no additional information.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Wordy; constraint needs stating once in Architecture where mechanism defined.
*   ***Proposed Edit:***
    *   Location: Lines 12, 30, 36
    *   Change: Remove redundancy; state "never write back" once in Architecture (line 30).

---

### ST-09 [egm-style] - Severity: Major
*   **Affected Scope:** Lines 30, 36, 54
*   **Discrepancy:** "Merge" used for two different operations: combining certificate lists (line 36: concatenation + re-sort) vs. combining gaps/warnings (line 54).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Word overloaded without distinction.
*   ***Proposed Edit:***
    *   Location: Line 54
    *   Change: Use "combine" or "unify" for gaps/warnings operation.

---

### ST-10 [egm-style] - Severity: Major
*   **Affected Scope:** Lines 5, 7 (Problem Statement)
*   **Discrepancy:** "can therefore corrupt" — "therefore" is filler; "can corrupt" is speculative hedging. Assumes cron job's snapshot is production DB (not stated).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Uncalibrated causal claim.
*   ***Proposed Edit:***
    *   Location: Line 7
    *   Change: "A one-off `check` run may overwrite observations in the production DB that a scheduled scan relies on." (Relocate consequence to Risks as measured statement.)

---

### ST-11 [egm-style] - Severity: Major
*   **Affected Scope:** Line 5 (Problem Statement)
*   **Discrepancy:** "documents that" is wordy; "states that" is direct.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Minor wording improvement.
*   ***Proposed Edit:***
    *   Location: Line 5
    *   Change: "The `certclock check` command **states that** `--db` reads..."

---

### ST-12 [egm-style] - Severity: Nit
*   **Affected Scope:** Lines 5, 13, 34
*   **Discrepancy:** "throwaway database" (lines 5, 13) vs. "temporary database" (line 34, architecture line 28).
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Inconsistent terminology.
*   ***Proposed Edit:***
    *   Location: Lines 5, 13, 34
    *   Change: Use "temporary database" consistently (matches architecture).

---

### ST-13 [egm-style] - Severity: Nit
*   **Affected Scope:** Lines 24, 28, 43, 47
*   **Discrepancy:** "temporary directory" (24), "temporary database" (28), "temp DB" (43, 47). Scratch location is a directory; database lives inside it.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Conflating directory and DB with same shorthand.
*   ***Proposed Edit:***
    *   Location: Lines 24, 28, 43, 47
    *   Change: Use "scratch directory" for directory, "temporary database" for DB inside. Avoid "temp DB".

---

### ST-14 [egm-style] - Severity: Nit
*   **Affected Scope:** Lines 27, 32
*   **Discrepancy:** "Open the production database **read-only**" — mode appended as adverbial phrase.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** "in read-only mode" is unambiguous (though per other findings, this phrasing should change to "normally but do not call ingest").
*   ***Proposed Edit:***
    *   Location: Lines 27, 32
    *   Change: Align with ST-03/CO-02: "Open the production database normally but do not call `ingest` on it."

---

### ST-15 [egm-style] - Severity: Nit
*   **Affected Scope:** Line 53 (Risks)
*   **Discrepancy:** "No additional memory beyond the second list" — comparison unclear.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Same as CO-06.
*   ***Proposed Edit:*** See CO-06.

---

### ST-16 [egm-style] - Severity: Nit
*   **Affected Scope:** Line 54 (Risks)
*   **Discrepancy:** "from one side" is vague.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** "from either inventory" is precise.
*   ***Proposed Edit:***
    *   Location: Line 54
    *   Change: "Report merge misses gaps/warnings from either inventory."

---

## Summary Table

| Finding-ID | Reviewer | Schwere | Entscheidung | Änderung/Begründung |
|------------|----------|---------|--------------|---------------------|
| ZO-01 | egm-zoom-out | Blocker | PROPOSE FIX | Case B uses StoredCert instead of ReportCert; must call explain() |
| ZO-02 | egm-zoom-out | Blocker | PROPOSE FIX | Owner rules ignored in Case B; fixed by calling explain() with assign_owners |
| ZO-03 | egm-zoom-out | Major | PROPOSE FIX | No fingerprint dedupe across inventories; double-counts certs |
| ZO-04 | egm-zoom-out | Major | PROPOSE FIX | Cross-inventory dependency analysis lost; fixed by single explain() on merged list |
| ZO-05 | egm-zoom-out | Nit | PROPOSE FIX | Implementation plan too detailed (Standard §3 violation) |
| ZO-06 | egm-zoom-out | Nit | PROPOSE FIX | Step 3 text contradicts code block |
| ZO-07 | egm-zoom-out | Nit | PROPOSE FIX | Nonexistent --db creates empty SQLite file; need guard/criterion |
| ZO-08 | egm-zoom-out | Nit | PROPOSE FIX | Promised test update not present |
| CO-01 | egm-comprehension | Blocker | PROPOSE FIX | Acceptance criteria require unchanged DB but no read-only mechanism |
| CO-02 | egm-comprehension | Major | PROPOSE FIX | "read-only (or open normally)" weakens requirement |
| CO-03 | egm-comprehension | Major | PROPOSE FIX | Promised re-sorting not performed in Case B |
| CO-04 | egm-comprehension | Major | PROPOSE FIX | Mis-scoped statement about which branches bypass build_report |
| CO-05 | egm-comprehension | Major | PROPOSE FIX | CheckOutcome and test helpers undefined in doc |
| CO-06 | egm-comprehension | Nit | PROPOSE FIX | Memory mitigation understated |
| CO-07 | egm-comprehension | Nit | PROPOSE FIX | Gap/warning merge types undefined |
| CO-08 | egm-comprehension | Nit | PROPOSE FIX | Private attribute _base_dir set without explanation |
| CO-09 | egm-comprehension | Nit | PROPOSE FIX | Test snippet relies on out-of-scope helpers |
| CO-10 | egm-comprehension | Nit | PROPOSE FIX | New failure modes in Case B unaddressed |
| CR-01 | egm-design | Blocker | PROPOSE FIX | Duplicate of ZO-01 |
| CR-02 | egm-design | High | PROPOSE FIX | Duplicate of ZO-03 |
| CR-03 | egm-design | Medium | PROPOSE FIX | Duplicate of ZO-02 |
| CR-04 | egm-design | Medium | PROPOSE FIX | weak_rsa_bits/max_validity_days unused in Case B |
| CR-05 | egm-design | Low | PROPOSE FIX | Duplicate of ZO-06 |
| CR-06 | egm-design | Low | PROPOSE FIX | CHANGELOG convention mismatch (## Unreleased not ## Fixed) |
| CR-07 | egm-design | Low | PROPOSE FIX | Error Behaviour misstates exception type (sqlite3.OperationalError not OSError) |
| CR-08 | egm-design | Low | PROPOSE FIX | "opened read-only" imprecise; opens normally |
| ST-01 | egm-structural | Major | PROPOSE FIX | Risks table incomplete (concurrency, read-write handle) |
| ST-02 | egm-structural | Nit | PROPOSE FIX | CLI help line 86 citation overreaches |
| ST-03 | egm-structural | Nit | PROPOSE FIX | Architecture presents rejected read-only option as live guidance |
| ST-04 | egm-structural | Nit | PROPOSE FIX | Architecture overstates merge step vs plan |
| ST-05 | egm-structural | Nit | PROPOSE FIX | Alternatives table imprecise on SQLite read-only semantics |
| ST-06 | egm-style | Blocker | PROPOSE FIX | Acceptance criteria don't verify read-only goal |
| ST-07 | egm-style | Blocker | PROPOSE FIX | Duplicate of ST-03 |
| ST-08 | egm-style | Major | PROPOSE FIX | Redundant "never write back" phrasing |
| ST-09 | egm-style | Major | PROPOSE FIX | "Merge" overloaded for two different operations |
| ST-10 | egm-style | Major | PROPOSE FIX | "can therefore corrupt" uncalibrated causal claim |
| ST-11 | egm-style | Major | PROPOSE FIX | "documents that" wordy |
| ST-12 | egm-style | Nit | PROPOSE FIX | "throwaway" vs "temporary" database inconsistency |
| ST-13 | egm-style | Nit | PROPOSE FIX | "temp DB" / "scratch directory" / "temporary database" inconsistency |
| ST-14 | egm-style | Nit | PROPOSE FIX | "read-only" phrasing (superseded by ST-03 fix) |
| ST-15 | egm-style | Nit | PROPOSE FIX | "No additional memory beyond the second list" unclear |
| ST-16 | egm-style | Nit | PROPOSE FIX | "from one side" vague |

## Round 1: Feature — Status
All findings classified as **PROPOSE FIX**. No findings contested (no factual errors or out-of-scope items identified). The design document requires substantial revision to fix technical correctness (Blockers ZO-01/02/CO-01/CR-01/CR-02/ST-06), align architecture with implementation (CO-02/03/04/CR-08/ST-03/04), complete risk analysis (ST-01), and improve editorial quality (remaining Nits/Majors).
---

## Round 2: Detailed Plan — Stage 8 (Intermediate Zoom Out) & Stage 9 (Implementation Readiness)

### Stage 8: Intermediate Zoom Out (egm-zoom-out) — All findings duplicate Round 1

| Finding-ID | Reviewer | Severity | Classification | Rationale |
|------------|----------|----------|----------------|-----------|
| ZO-01 (dup) | egm-zoom-out | Blocker | PROPOSE FIX | Duplicate of ZO-01 — merged `Report` from `StoredCert` bypassing `explain()` |
| ZO-02 (dup) | egm-zoom-out | Blocker | PROPOSE FIX | Duplicate of ZO-02 — owner rules never applied in Case B |
| ZO-03 (dup) | egm-zoom-out | Major | PROPOSE FIX | Duplicate of ZO-03 — no fingerprint dedupe across inventories |
| ZO-04 (dup) | egm-zoom-out | Major | PROPOSE FIX | Duplicate of ZO-04 — cross-inventory dependency analysis lost |
| ZO-05 (dup) | egm-zoom-out | Nit | PROPOSE FIX | Duplicate of ZO-05 — implementation plan violates Anti-Weeds (§3) |
| ZO-06 (dup) | egm-zoom-out | Nit | PROPOSE FIX | Duplicate of ZO-06 — Step 3 text contradicts code block |
| ZO-07 (dup) | egm-zoom-out | Nit | PROPOSE FIX | Duplicate of ZO-07 — nonexistent `--db` creates empty SQLite file |
| ZO-08 (dup) | egm-zoom-out | Nit | PROPOSE FIX | Duplicate of ZO-08 — promised test update not present |

### Stage 9: Implementation Readiness — egm-implementation-readiness

| Finding-ID | Reviewer | Severity | Classification | Rationale |
|------------|----------|----------|----------------|-----------|
| IR-01 | egm-impl-readiness | Blocker | PROPOSE FIX | Duplicate of ZO-01 — type mismatch `StoredCert` vs `ReportCert` |
| IR-02 | egm-impl-readiness | Blocker | PROPOSE FIX | Duplicate of ZO-03 — no deduplication strategy |
| IR-03 | egm-impl-readiness | Major | PROPOSE FIX | Duplicate of CO-04 — `Config` creation precedes case split |
| IR-04 | egm-impl-readiness | Major | PROPOSE FIX | Duplicate of ZO-02 — owner assignment omitted in Case B |
| IR-05 | egm-impl-readiness | Nit | PROPOSE FIX | Duplicate of ZO-06 — "assignment" vs constructor argument |
| IR-06 | egm-impl-readiness | Nit | PROPOSE FIX | Duplicate of ZO-08 — test update underspecified |

### Stage 9: Implementation Readiness — egm-codebase-details

| Finding-ID | Reviewer | Severity | Classification | Rationale |
|------------|----------|----------|----------------|-----------|
| CD-01 | egm-codebase-details | Critical | PROPOSE FIX | Duplicate of ZO-01 — type mismatch `StoredCert` vs `ReportCert` |
| CD-02 | egm-codebase-details | Critical | CONTEST | Finding states "Only certificates has the type mismatch" — this is a clarification that gaps/warnings are compatible, not a new defect |
| CD-03 | egm-codebase-details | High | CONTEST | Missing `tempfile`/`Path` imports — verified already present in `check.py:18-20` |
| CD-04 | egm-codebase-details | High | CONTEST | `Report` import "incomplete" — `Gap` used as runtime value, not type annotation; no code change needed |
| CD-05 | egm-codebase-details | Medium | PROPOSE FIX | Duplicate of ZO-06/CO-04 — `Config.database` assignment confusion |
| CD-06 | egm-codebase-details | Medium | CONTEST | Exit code for `OSError` — verified correct (`EXIT_ERROR=3` caught) |
| CD-07 | egm-codebase-details | Medium | CONTEST | Test helper `_cert_file` — verified correct (same test file) |
| CD-08 | egm-codebase-details | Medium | CONTEST | `mint`/`LocalTlsServer` — verified correct (imported in test file) |
| CD-09 | egm-codebase-details | Low | PROPOSE FIX | Duplicate of ZO-08 — existing test update needed |
| CD-10 | egm-codebase-details | Low | CONTEST | README "No change needed" — subjective, not a design defect |
| CD-11 | egm-codebase-details | Low | CONTEST | CHANGELOG exists — verified, not an issue |
| CD-12 | egm-codebase-details | Low | CONTEST | Smoke test path — verified, not an issue |

### Stage 9: Implementation Readiness — egm-style

| Finding-ID | Reviewer | Severity | Classification | Rationale |
|------------|----------|----------|----------------|-----------|
| ST-01 (dup) | egm-style | Major | PROPOSE FIX | Duplicate of CO-02/CR-08/ST-03 — parenthetical weakens requirement |
| ST-02 (dup) | egm-style | Major | PROPOSE FIX | Duplicate of ST-03 — speculative "helper that merges two Report objects" |
| ST-03 (dup) | egm-style | Major | PROPOSE FIX | Duplicate of ST-05 — SQLite read-only URI claim uncalibrated |
| ST-04 | egm-style | Major | PROPOSE FIX | NEW — "Certificates are already loaded" asserts implementation detail; calibrate to "`Inventory.certificates()` loads certificates into memory" |
| ST-05 | egm-style | Major | PROPOSE FIX | NEW — test comment "edge cert is within 7 days" should reference `crit_days` config |
| ST-06 | egm-style | Major | PROPOSE FIX | NEW — smoke test verification "size unchanged" not concrete; specify `stat -c%s` |
| ST-07 (dup) | egm-style | Nit | PROPOSE FIX | Duplicate of ST-10/ST-12 — filler words ("therefore", "temporary", "already") |
| ST-08 | egm-style | Nit | PROPOSE FIX | NEW — jargon "touches only" → "modifies only" |
| ST-09 | egm-style | Nit | PROPOSE FIX | NEW — synonym redundancy "replaces"/"deleting" → pick one |
| ST-10 | egm-style | Nit | PROPOSE FIX | NEW — subjective "simpler and faster" → "avoids extra I/O and disk usage" |

### Round 2 Summary

| Reviewer | Blocker | Major | Nit | Contested |
|----------|---------|-------|-----|-----------|
| egm-zoom-out (Stage 8) | 2 | 2 | 4 | 0 |
| egm-impl-readiness (Stage 9) | 2 | 2 | 2 | 0 |
| egm-codebase-details (Stage 9) | 0 | 1 | 0 | 6 |
| egm-style (Stage 9) | 0 | 6 | 4 | 0 |
| **Total (unique, new)** | **0** | **3** | **4** | **6** |

No new Blockers in Round 2; all Blockers were duplicates of Round 1 findings. Three new Majors (ST-04, ST-05, ST-06) and four new Nits (ST-08, ST-09, ST-10, plus one duplicate) require fixes. Six findings contested as clarifications or verified-correct items.
