# Stage 6: Comprehension Test
### Reviewer: egm-comprehension (Modell: `kilo/kilo-auto/free`, frischer Prozess)



I've read the persona file, the OpenCode adapter instructions, and the target document. Here is the comprehension review.

## What this proposes

`certclock check --db <file>` currently writes ad-hoc observations collected via `--host`/`--path` back into the production database file, overwriting the `tls`/`tls-chain`/`file` sources that a scheduled scan relies on. The fix makes `--db` never write back: with no `--host`/`--path` it reads the production DB and builds the report directly; with `--host`/`--path` it collects into a **temporary** DB and merges production + ad-hoc data in memory (concatenating certificates, gaps, and warnings into a new `Report`) without touching the production file; with no `--db` the existing throwaway-temp-DB behavior is unchanged. Only `src/certclock/check.py` is modified.

## How the existing system works, per this document

`run_check` builds a `Config`, then — when `db` is given — opens that SQLite file through `Inventory`, ingests any collected `--host`/`--path` data into it, and passes the inventory to `build_report` + `evaluate`. When `db` is `None` it instead creates a temporary DB in a scratch directory. `Inventory.__init__` runs `executescript(_SCHEMA)` on whatever database it opens. The production DB is a SQLite file produced by `collect`/`scan` and consumed by `check`.

## Findings

**1. Severity: 🔴 Blocker — Internal contradiction between the implementation and the acceptance criteria**
Affected scope: Lines 117–127 (Cases A and B) vs. lines 59–62 (acceptance criteria 1–3) and line 42 (alternatives table).
The acceptance criteria require the production DB's **mtime and size to be unchanged** in all three `--db` scenarios. But the plan's Cases A and B open the production DB via `with Inventory(db) as ...`, and the alternatives table itself acknowledges that `Inventory.__init__` runs `executescript(_SCHEMA)` against that file (line 42). The plan offers no read-only opening mechanism for the production DB, so the proposed code may well write to (and change) the very file it promises to leave untouched. The doc never reconciles this; the test it proposes (line 279, compare size/mtime) would likely expose it.

**2. Severity: 🟠 Major — The "read-only (or open normally)" parenthetical weakens the requirement**
Affected scope: Line 27, implemented at line 124.
The architecture states the production DB should be opened "read-only (or open normally but do not call `ingest` on it)." These are not equivalent: opening normally still runs the schema script (see finding 1). The plan then silently takes the weaker branch (`with Inventory(db) as prod_inventory`, line 124) without noting that it no longer satisfies "read-only." The parenthetical reads as a concession that undermines the goal.

**3. Severity: 🟠 Major — Promised re-sorting is not performed**
Affected scope: Line 36 vs. lines 141–156.
The architecture says merging is "a simple list concatenation followed by re-sorting." The Case B implementation concatenates `prod_certs + temp_certs` and passes the raw list into a `Report` constructor with no sort. Report order will then differ from the single-inventory path (Case A, line 119, and Case C, line 168), producing inconsistent output for the same certificates depending on which path ran.

**4. Severity: 🟠 Major — Mis-scoped statement about which branches bypass `build_report`**
Affected scope: Line 174 vs. lines 117–169.
Line 174 claims the `database` field is unused "for Cases B and C since we don't pass a DB path to `build_report` in those branches." But Case C (lines 160–169) **does** call `build_report(inventory, config, now)`, as does Case A (line 119). Only Case B bypasses it. The statement is therefore wrong for two of the three cases, and the instruction to "remove the `config.database = db or ""` assignment" describes a change to code not shown in that form (the value is set in the `Config(...)` constructor at line 104).

**5. Severity: 🟠 Major — `CheckOutcome` and test helpers are undefined**
Affected scope: Lines 96, 120, 157, 169 (`CheckOutcome`); lines 200–276 (`EXIT_OK`, `EXIT_CRIT`, `EXIT_WARN`, `_cert_file`, `mint`, `LocalTlsServer`, `utcnow`, `dt`, `Gap`).
The return type `CheckOutcome` is used in the signature and its `.report` attribute is dereferenced in the test (line 262), but the document never defines what it is or what fields it carries. The same applies to the exit-code constants and the test fixtures, so the test snippet is not self-contained and the merge's type compatibility (`list[Gap]` vs. `Report.gaps`) is unverifiable from the document alone.

**6. Severity: 🔵 Nit — Memory-usage mitigation is understated**
Affected scope: Line 53 vs. lines 125–142.
The mitigation says "No additional memory beyond the second list," but Case B holds `prod_certs` **and** `temp_certs` in memory at the same time — the entire production certificate list is duplicated, not merely an incremental second list.

**7. Severity: 🔵 Nit — Gap/warning merge types are undefined**
Affected scope: Lines 54, 142–144, 178–185.
The risk table and the implementation both concatenate `Inventory.gaps()` / `Inventory.warnings()` results into `Report` fields, but the return types of those methods and the `Gap`/`Report` field types are never defined in the document, so the merge's type compatibility can only be verified by leaving the scope and reading `models.py`.

**8. Severity: 🔵 Nit — Private attribute set without explanation**
Affected scope: Line 113.
`config._base_dir = Path.cwd()` sets a private attribute with no stated purpose, leaving the reader to guess whether it affects temp-DB path resolution or collector behavior.

**9. Severity: 🔵 Nit — Test snippet relies on out-of-scope helpers**
Affected scope: Lines 200–276.
The pytest examples use `_cert_file`, `mint`, `LocalTlsServer`, `utcnow`, `dt`, and the `EXIT_*` constants without defining or importing them, so the tests as written cannot be evaluated for correctness from the document.

**10. Severity: 🔵 Nit — New failure modes in Case B are unaddressed**
Affected scope: Lines 129–157 vs. lines 189–194.
The error-behaviour section claims all error paths are unchanged, but Case B introduces a second `Inventory` open and a `TemporaryDirectory` whose failures (e.g., temp dir creation failing after the production DB was already opened) are not covered by the listed `OSError` → exit 3 mapping.

