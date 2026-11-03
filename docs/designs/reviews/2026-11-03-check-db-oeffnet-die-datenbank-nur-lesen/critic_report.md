# Stage 7: Critic Review (FeatureRange 1..67)
### Reviewer: egm-design (Modell: `kilo/kilo-auto/free`, frischer Prozess)



I'll start by reading the persona/instruction file, then the target file, standard, and context.
Let me verify the code claims in the design doc against the actual source files.
✗ Grep "check|help_text|--db|--host|--path|86" failed in src/certclock/cli.py
Error: Model tried to call unavailable tool 'invalid'. Available tools: glob, read.
I read the persona file (`opencode.md`), the target design doc, the feature-spec standard, and the README, then verified every code/test reference against the actual repo. I used only `read` and `glob` (the permitted reviewer tools; `grep` was unavailable). Findings below.

## Verdict

The document **passes the feature-spec-standard.md structurally** (Problem Statement, Goals, Non-Goals, Architecture, 4 alternatives with concrete rationales, Risks & Mitigations are all present). It **fails on technical correctness**: the proposed Case B implementation cannot work, and it contradicts the doc's own field description.

---

### BLOCKER — Proposed Case B builds a `Report` from `StoredCert`, not `ReportCert`

- **Target lines:** 36, 123–157 (esp. 125, 137, 142, 149); contradicted by target line 180.
- **Discrepancy:** The proposed code does `prod_certs = prod_inventory.certificates()` (line 125) and `temp_certs = temp_inventory.certificates()` (line 137), then `all_certs = prod_certs + temp_certs` (line 142) and `Report(certificates=all_certs, …)` (line 149). `Inventory.certificates()` returns `list[StoredCert]` (`src/certclock/inventory.py:144`), but `Report.certificates` is typed `list[ReportCert]` (`src/certclock/models.py:137`, and the doc itself says so at target line 180). `StoredCert` (`models.py:69–90`) has **none** of `days_remaining`, `bucket`, `problems`, `sources`, `owner`, `service`, `owner_note`, `dependency_note`.
- **Rationale:** Every consumer crashes. `evaluate()` → `status_code(cert, …)` reads `cert.days_remaining` (`check.py:51`, `outputs/markdown.py:81`); `render_text` reads `cert.days_remaining` (`check.py:113`) and `cert.sources` (`check.py:120`); `render_markdown` reads `cert.days_remaining` (`markdown.py:38`); `Report.summary()` reads `cert.bucket` (`models.py:155`). Even `fail_on="never"` crashes, because `evaluate` still iterates certs (`check.py:49–51`). Case B is non-functional for every output format. The doc's line 185 ("The constructor call above matches") is false for types even though line 180 correctly states the type — an internal contradiction.
- **Also:** Bypassing `build_report` means `explain()` is never called, so **no findings are ever computed** in Case B: no expiry/`expires_within_*`, no `weak_key`, no `sha1`, no `long_validity`, no `self_signed`, no issuer/dependency notes. Acceptance criteria 2 and 3 ("evaluates the union … cert is within 7 days → CRIT") cannot pass; criterion 5 ("all pytest pass") cannot pass — the proposed `test_check_db_merge_preserves_both_gaps_and_warnings` (target line 261) calls `run_check(...)` and would raise `AttributeError` inside `evaluate`.

**Suggested fix:** Run `explain()` on each inventory's certs (with owners applied) to get `ReportCert` lists *before* merging, then concatenate and re-sort — or merge at the `StoredCert` level (deduped) and call `explain()` once on the merged list. Either way, `build_report`'s owner/owner-file logic must be preserved in Case B.

---

### HIGH — Merge produces duplicate certificates (no "union" dedup)

- **Target lines:** 36, 142.
- **Discrepancy:** The doc says the ad-hoc run "evaluates the **union**" (line 60; also "merge … list concatenation", line 36). The implementation is bare concatenation (`prod_certs + temp_certs`) with no fingerprint dedup. `Inventory` dedups *within* one DB (primary key, `inventory.py:223`), but not across two.
- **Rationale:** `check --db prod.db --host example.test:443` where example.test's cert is already in `prod.db` (the common case — prod.db is the scheduled-scan snapshot) yields the same leaf (and its chain) twice. `Report.summary()` double-counts (`models.py:154`), and certs get double-flagged. This directly breaks acceptance criterion 2's "union" wording and the `summary()` counts used by `render_text` (`check.py:105`).

---

### MEDIUM — `--owners` is accepted and configured but silently ignored in Case B

- **Target lines:** 105, 124, 147–156.
- **Discrepancy:** `run_check` accepts `owners` and sets `config.owners_file = owners` (target line 105; real `cli.py:209` passes `owners=args.owners`). But Case B never calls `load_owners`/`assign_owners` (the only caller is `build_report`, `pipeline.py:56–65`). The merged `Report` is constructed with `owner=None, service=None, owner_note=None` for every row.
- **Rationale:** `check --db prod.db --host … --owners owners.yml` would silently produce an unowned report. Same class of bug as the `explain()` omission.

---

### MEDIUM — `weak_rsa_bits` / `max_validity_days` are set but unused in Case B

- **Target lines:** 109–111, 147–156.
- **Discrepancy:** `Config` is built with `weak_rsa_bits=2048` and `max_validity_days=…` (target lines 109–111; real `check.py:86–87`), and `Report` is constructed directly (target line 147) instead of via `build_report`, which is the only code that passes these into `explain()` (`pipeline.py:63–64`).
- **Rationale:** In Case B, `weak_key` and `long_validity` findings are never produced, so `--max-validity-days` and the 2048-bit threshold have no effect. Same root cause as the BLOCKER.

---

### LOW — Step 3 contradicts the proposed code; "assignment" does not exist

- **Target lines:** 174 vs. 103–112.
- **Discrepancy:** Step 3 says "Remove the `config.database = db or ""` assignment for Cases B and C", but the code block still passes `Config(database=db or "", …)` (target line 104). There is also no such post-construction assignment in the real code — it's a constructor argument (`check.py:80`).
- **Rationale:** Internal inconsistency; harmless in practice (`database` is unused in Case B/C), but the plan and the code disagree.

---

### LOW — CHANGELOG instruction does not match the file's convention

- **Target line:** 284.
- **Discrepancy:** The doc says add the entry "under `## Fixed`". The real `CHANGELOG.md` has no `## Fixed` section; its convention is `## Unreleased` (`CHANGELOG.md:3`), under which the existing entry sits (`CHANGELOG.md:5`).
- **Rationale:** Cosmetic; the entry would need a new `## Fixed` heading or go under `## Unreleased`.

---

### LOW — "Error Behaviour" misstates the `--db` OSError path

- **Target line:** 190.
- **Discrepancy:** The doc claims "Unreadable `--db` file: `Inventory.__init__` raises `OSError` → caught in `_cmd_check` → exit 3." In reality `sqlite3.connect` raises `sqlite3.OperationalError`, a subclass of `sqlite3.Error`/`Exception`, **not** `OSError`; `_cmd_check` only catches `(OSError, ValueError, RuntimeError)` (`cli.py:216`), so an unreadable DB would surface as an unhandled traceback rather than exit 3.
- **Rationale:** Pre-existing behavior, not introduced by this design, but the doc asserts it as fact. (Note: `Inventory.__init__` does create missing parent dirs, `inventory.py:78–79`, so "file in missing dir" is handled; the claim is only wrong for permission/lock failures.)

---

### LOW — "opened read-only" is imprecise

- **Target lines:** 36, 124.
- **Discrepancy:** The architecture says the production DB is "opened read-only", but the code opens it with `Inventory(db)` normally (`inventory.py:76–82` runs `executescript(_SCHEMA)` on every open); read-only-ness is only by convention (no `ingest` call). The Alternatives table (target line 42) correctly explains why a true `readonly=true` URI was rejected, so this is wording, not a design error.

---

### Verified-accurate references (no action needed)

Target lines 5, 10–12, 24, 27 (`tls.py:27`), 36/76 (`run_check` 63–100), 72 (`src/certclock/check.py` only), 172 (`Report` import at `check.py:29`), 178–185 (field list matches `models.py:134–143`), 279 (exact test name `test_check_against_existing_db_with_markdown` at `tests/test_check.py:89`), 270–276 (output format matches `check.py:107–109`). The problem statement's corruption claim is confirmed: with `--db`, `database = db` (`check.py:92`) and `ingest` writes into the production file (`check.py:93–98`), and `replace_sources`/`_delete_orphans` (`inventory.py:100–106`, `433–439`) genuinely delete prior `tls`/`tls-chain`/`file` observations and orphaned certs — including gaps/warnings on a failed collection (e.g. closed port → `add_gap` INSERTs into prod DB, `inventory.py:126–130`).

### Out-of-scope observation (not a doc discrepancy)

`src/certclock/pipeline.py:123` contains an anomalous comment (`# Not checked: tests were not run in this read-only review.`) that is not part of the design doc's scope and does not change behavior.

---

**Bottom line:** The spec is well-structured and the read-only goal is correct, but the proposed Case B code is fundamentally broken (StoredCert vs ReportCert, no `explain()`, no owner/threshold handling, no dedup) and cannot satisfy its own acceptance criteria 2/3/5. Fix the merge to go through `explain()` with fingerprint dedup and preserved owners/gaps/warnings, then re-review.

### Reviewer: egm-structural (Modell: `kilo/kilo-auto/free`, frischer Prozess)



I read the persona file (`agents/structural.md` → REVIEW mode), the target document (lines 1–67), the feature-spec standard, the GoldfishContext README, and verified the cited source locations in `check.py`, `inventory.py`, `tls.py`, `cli.py`, `models.py`, `pipeline.py`, and `tests/test_check.py` (read-only, no edits, no test execution).

## Structural audit — `docs/designs/2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md` (lines 1–67)

**Structure check (all pass):** H1 title at line 1; five H2 sections follow with no skipped levels and no stray H3s — `## Problem Statement` (3), `## Goals` (9), `## Non-Goals` (16), `## Proposed Architecture` (22), `## Alternatives Considered` (38), `## Risks & Mitigations` (49), `## Acceptance Criteria` (57). All mandatory sections named in the standard are present. Bullets are consistently `-`; ordered lists use `1.` where ordering matters (Proposed Architecture, Acceptance Criteria). Both tables (lines 40–45, 51–55) are well-formed — header, separator, and every data row have matching pipe counts and cell counts. No links exist in this range, so the link-compliance vector is vacuously satisfied. No unclosed fences or malformed syntax in 1–67.

### Findings

**1. Major — Risks & Mitigations incomplete vs. the standard**
- **Scope:** `## Risks & Mitigations`, lines 49–55
- **Discrepancy:** The standard requires the spec to "explicitly call out its own constraints" and "identify potential failure modes … and how they will be mitigated." The table covers memory/scalability, the merge losing gaps/warnings, and test breakage. It does **not** address the failure modes that matter most for this spec's central promise ("no writes to the production database"):
  - The production DB is opened **read-write** (the read-only URI was rejected in the Alternatives table, line 42), so the "no writes" guarantee rests on *restraint* (never calling `ingest`), not on a read-only handle. `Inventory.__init__` still runs `conn.executescript(_SCHEMA)` (inventory.py:82) — idempotent today, but an unmitigated foot-gun: any future change to `_SCHEMA` or `Inventory.__init__` that writes would silently write to production.
  - **Concurrency/locking is unaddressed.** `check --db` shares the production snapshot with scheduled `collect`/`scan`. A concurrent writer holding the SQLite lock can turn a read into `sqlite3.OperationalError: database is locked` → exit 3, or stall the writer. The Detailed Implementation Plan opens the DB in a `with Inventory(db)` block (design line 124) with no timeout/`busy_timeout`, so this is a live, unplanned failure mode.
- **Rationale:** The acceptance criteria (line 59) assert "mtime and size unchanged" — a behavioural check, not a mechanical guarantee. A fresh reader cannot confirm from this spec how no-writes is actually enforced or what happens when the DB is locked. Per the standard's "must" language, this is a gap in the mandatory Risks & Limits content, not a cosmetic omission.

**2. Nit — Line 5 attributes throwaway behaviour to the wrong source**
- **Scope:** `## Problem Statement`, line 5
- **Discrepancy:** "…documents that `--db` reads an existing inventory **or collect ad hoc into a throwaway database** (CLI help line 86, `check.py` docstring lines 10–12)." Verified: `cli.py:86` is `check.add_argument("--db", default=None, help="read an existing inventory")` — it states only the read path. The ad-hoc/throwaway wording comes solely from the `check.py` docstring (lines 10–12). Citing "CLI help line 86" as co-evidence for the throwaway claim is imprecise.
- **Rationale:** Minor accuracy/traceability issue; the claim itself is true, the citation overreaches.

**3. Nit — Line 27 presents a rejected option as live architecture guidance**
- **Scope:** `## Proposed Architecture`, line 27
- **Discrepancy:** "Open the production database **read-only** (or open normally but do not call `ingest` on it)." The read-only branch is later explicitly rejected in the Alternatives table (line 42) because `Inventory.__init__` runs `executescript(_SCHEMA)`, which would fail on a read-only handle. So the architecture section offers a path the spec itself rules out.
- **Rationale:** Not a structural markdown defect, but it leaves the primary architectural statement internally contradictory. The surviving guidance should be "open normally, never call `ingest`."

**4. Nit — Line 36 overstates the merge step vs. the implementation plan**
- **Scope:** `## Proposed Architecture`, line 36
- **Discrepancy:** "…merging is a simple list concatenation followed by re-sorting." The concrete plan (design lines 142–156, outside the audited range but referenced by this sentence) does `all_certs = prod_certs + temp_certs` and passes the flat list straight into the `Report` constructor with no re-sort in the merge. Sorting is deferred to the renderers (`check.py:113`).
- **Rationale:** The high-level claim and the plan disagree about whether re-sorting is part of the merge. Harmless in effect, but the sentence as written is not accurate to the plan it points at.

**5. Nit — Line 42 imprecise about SQLite read-only semantics**
- **Scope:** `## Alternatives Considered`, line 42
- **Discrepancy:** "SQLite read-only URI still allows `PRAGMA` and schema creation." A `mode=ro` URI cannot create schema; the actual, correct blocker is that `Inventory.__init__` calls `executescript(_SCHEMA)` (inventory.py:82), which fails on a read-only connection.
- **Rationale:** The rejection rationale reaches the right conclusion, but its technical premise is loose. The standard demands "concrete technical … trade-offs"; this one is half-concrete.

**Standard compliance summary:** The Alternatives Rule is satisfied — four rejected options, each with a concrete technical/scope rationale, and no rejection attributed to a maintainer without a linked issue/PR. Structure, heading hierarchy, tables, and list formatting are clean. The single Major gap is in the Risks & Limits content (concurrency + read-write-handle constraints), which the standard makes mandatory.

Note: I did not run `pytest`/`ruff`; per the read-only mandate and because this is a document review, no verification was executed. Code-line citations above were checked against the current source and all verified ones (check.py:91–98, inventory.py:100–112, tls.py:27, check.py docstring 10–12, inventory.py:82, check.py:113) are accurate.

### Reviewer: egm-style (Modell: `kilo/kilo-auto/free`, frischer Prozess)



## Review Findings

**Target:** `docs/designs/2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md` (lines 1–67)
**Reviewer:** Style Goldfish (egm-style)
**Mode:** REVIEW — Document Audit

---

### BLOCKER 1 — Acceptance criteria do not verify the stated goal
- **Lines:** 59–62 (Acceptance Criteria)
- **Discrepancy:** The design's primary goal (line 1) is that `--db` opens the database **read-only**. Every acceptance criterion verifies only that `prod.db` is *unchanged* (mtime/size). File invariance does not imply read-only opening; a normal open that simply skips `ingest` would also leave the file unchanged. No criterion tests that write operations are actually rejected or that the DB handle is opened read-only.
- **Rationale:** The criteria measure a weaker invariant than the goal. The design must add a criterion that observes write behaviour (e.g., an attempted write during the check is denied, or the open mode is confirmed read-only).
- **Severity:** Blocker

---

### BLOCKER 2 — Architecture contradicts the Alternatives table
- **Lines:** 27 (Proposed Architecture) vs. line 42 (Alternatives Considered)
- **Discrepancy:** Line 27 says: *"Open the production database **read-only** (or open normally but do not call `ingest` on it)."* But line 42 rejects the read-only approach outright: *"SQLite read-only URI still allows `PRAGMA` and schema creation; `Inventory.__init__` runs `executescript(_SCHEMA)` which would fail."* The architecture then proposes the very thing the alternatives claim is not viable, without reconciling the two.
- **Rationale:** The parenthetical "or open normally but do not call `ingest`" is the actual viable path, but it is buried as an afterthought. The alternatives table should be updated to reflect that opening normally and skipping `ingest` is the chosen mechanism, and the architecture should state it as the primary approach rather than pairing it with a rejected option.
- **Severity:** Blocker

---

### MAJOR 1 — Redundant merge / write-back phrasing
- **Lines:** 12, 30
- **Discrepancy:** Line 12: *"merge with the existing inventory in memory for the check, and **never write back** to the production database file."* Line 30: *"Build the report from a **merged view** of both databases."* The "in memory" / "never write back" constraint is stated three times (lines 12, 30, 36) with no additional information each time.
- **Rationale:** Wordy. The constraint needs stating once, in the Architecture section, where the mechanism is defined. Goals should state *what*; Architecture states *how*.
- **Severity:** Major

---

### MAJOR 2 — "Merge" is imprecise and overloaded
- **Lines:** 30, 36, 54
- **Discrepancy:** Line 30 uses "merged view"; line 36 defines merge as *"list concatenation followed by re-sorting"*; line 54 uses "merge" for combining gaps/warnings. The word carries two different operations (combining certificate lists vs. combining gap/warning lists) without distinction.
- **Rationale:** Use "combine" or "unify" for the gaps/warnings operation (line 54) to distinguish it from the certificate-list concatenation defined at line 36.
- **Severity:** Major

---

### MAJOR 3 — "can therefore corrupt" — uncalibrated causal claim
- **Lines:** 5, 7
- **Discrepancy:** Line 5 describes the buggy behaviour factually. Line 7: *"A one-off `check` run **can therefore corrupt** the production snapshot that a cron job relies on."* The word "therefore" is filler, and "can corrupt" is a speculative hedging with no concrete operator decision attached. It also assumes the cron job's snapshot is the production DB — an assumption not stated in the problem statement.
- **Rationale:** Either state the consequence as a measured risk (e.g., "may overwrite observations in the production DB") or relocate it to Risks. Remove "therefore."
- **Severity:** Major

---

### MAJOR 4 — "documents that" is wordy
- **Line:** 5
- **Discrepancy:** *"The `certclock check` command **documents that** `--db` reads..."*
- **Rationale:** "States that" is direct. "Documents that" implies a separate specification act; the help text and docstring *are* the specification.
- **Severity:** Major

---

### NIT 1 — "throwaway database" vs. "temporary database" inconsistency
- **Lines:** 5, 13, 34
- **Discrepancy:** Line 5 uses "throwaway database"; lines 13 and 34 use "temporary database." The architecture (line 28) uses "temporary database." Goal 3 (line 13) restates the unchanged behaviour using the alternative term.
- **Rationale:** Pick one term and use it consistently. "Temporary database" matches the architecture's established terminology.
- **Severity:** Nit

---

### NIT 2 — "temp DB" / "scratch directory" / "temporary database" inconsistency
- **Lines:** 24, 28, 43, 47
- **Discrepancy:** Line 24: "temporary directory"; line 28: "temporary database"; line 43: "temp DB"; line 47: "temp DB." The scratch location is a directory; the database lives inside it. Conflating the two with the same shorthand ("temp DB") is imprecise.
- **Rationale:** Use "scratch directory" for the directory (as line 24 does) and "temporary database" for the DB inside it. Avoid "temp DB" entirely.
- **Severity:** Nit

---

### NIT 3 — "Open the production database read-only" phrasing
- **Line:** 27, 32
- **Discrepancy:** *"Open the production database **read-only**"* — the mode is appended as an adverbial phrase rather than stated as a mode.
- **Rationale:** *"Open the production database in read-only mode"* is unambiguous.
- **Severity:** Nit

---

### NIT 4 — "No additional memory beyond the second list"
- **Line:** 53
- **Discrepancy:** *"No additional memory **beyond the second list**."* The comparison is unclear — beyond the second list *compared to what?*
- **Rationale:** *"No additional memory beyond the second list's own footprint"* or restructure to compare against the single-inventory case explicitly.
- **Severity:** Nit

---

### NIT 5 — "from one side" is vague
- **Line:** 54
- **Discrepancy:** *"Report merge misses gaps/warnings from one side."*
- **Rationale:** *"from either inventory"* is precise.
- **Severity:** Nit

---

### Summary

| Severity | Count |
|----------|-------|
| Blocker | 2 |
| Major    | 4 |
| Nit      | 5 |

**Recommended editorial actions:**
- **DROP** the "therefore" at line 7; relocate the corruption consequence to Risks as a measured statement.
- **CALIBRATE** the acceptance criteria (lines 59–62) to include an explicit read-only verification criterion.
- **RELOCATE** the read-only opening caveat: the alternatives table (line 42) should acknowledge that opening normally and skipping `ingest` is the chosen path, and line 27 should lead with that approach rather than pairing it with a rejected option.
- **KEEP** the rest of the document — the problem statement, goals, non-goals, and the in-memory merge approach are sound and evidence-backed.

