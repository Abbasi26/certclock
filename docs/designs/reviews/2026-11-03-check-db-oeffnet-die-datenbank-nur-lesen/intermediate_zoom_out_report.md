# Stage 8: Intermediate Zoom Out
### Reviewer: egm-zoom-out (Modell: `kilo/nvidia/nemotron-3-ultra-550b-a55b:free`, frischer Prozess)



Based on my review of the target document, the zoom-out standard, and the prior zoom-out report, here are my findings:

---

## Review: `2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md` vs Zoom-Out Standard

**Verdict: The prior report's Blockers and Majors remain unaddressed. The Detailed Implementation Plan (lines 141–157) is still functionally broken as written.**

---

### BLOCKER — Lines 147–156: Merged `Report` constructed from `StoredCert` objects, bypassing `explain()`

**Location:** Design lines 141–156 (Case B implementation)  
**Standard violated:** §4 Leverage Existing — bypasses `build_report`/`explain`/`assign_owners` pipeline

The plan collects `prod_certs` / `temp_certs` via `Inventory.certificates()` → `list[StoredCert]`, concatenates them, and passes directly to `Report(certificates=all_certs, …)`. But `Report.certificates` is typed `list[ReportCert]` (`models.py:137`), and `StoredCert` (`models.py:70`) lacks `days_remaining`, `bucket`, `problems`, `owner`, `service`, `dependency_note`, `sources`. This causes `AttributeError` in:
- `evaluate()` → `status_code()` → `cert.days_remaining`
- `render_text()` → `cert.sources`, `cert.problems`
- `render_json_outcome()` → `cert.sources`, `cert.problems`

**Identical to prior report lines 15–26.** No mitigation added.

---

### BLOCKER — Lines 147, 103–112, 174: Owner rules never applied in Case B

**Location:** Design lines 103–112 (Config construction), 147–156 (Case B)  
**Standard violated:** §4 Leverage Existing / §1 Root Problem Focus

`build_report` (`pipeline.py:56–58`) loads owners via `config.resolve(config.owners_file)` and passes `assign_owners(stored, rules)` to `explain()`. Case B constructs `Report` directly — `Config(owners_file=owners, …)` is set but never read. `check --db prod.db --host … --owners owners.yml` silently stops assigning owners/service/notes — a behaviour regression vs. single-DB path.

**Identical to prior report lines 32–36.** No mitigation added.

---

### MAJOR — Lines 142–144: No deduplication across inventories

**Location:** Design line 142: `all_certs = prod_certs + temp_certs`  
**Standard violated:** §2 Simplicity (correctness) / §4 Leverage Existing (production DB dedupes by fingerprint)

Same fingerprint can appear twice (e.g., `collect files --db prod.db --path X` then `check --db prod.db --path X`). Counted twice in `report.summary()`, listed twice. Prior report lines 38–41 flagged this; design's risk table (lines 49–55) and tests (lines 250–268) still don't cover it.

**No mitigation added.**

---

### MAJOR — Lines 146–157: Cross-inventory dependency analysis lost

**Location:** Design lines 146–157 (merged Report construction)  
**Standard violated:** §4 Leverage Existing — `explain()` indexes all certs together for issuer matching

If fixed by calling `explain()` per-inventory and concatenating `ReportCert` rows, a leaf from ad-hoc collection whose issuer lives only in production DB would be wrongly flagged `issuer_not_in_inventory` and lose `issuer_expires_first`. Correct merge requires combined `StoredCert` list → single `explain()` call.

**Identical to prior report lines 44–47.** No mitigation added.

---

### NIT — Lines 84–170: Implementation plan violates Anti-Weeds (Premature Detail)

**Location:** Entire "Detailed Implementation Plan" section (lines 84–170)  
**Standard violated:** §3 Anti-Weeds / Altitude Control

Full refactored `run_check` source listing, five inline pytest functions, per-step commentary. High-level sections should focus on architecture/interfaces/data flows. The code listing became the spec — which is where the three errors above survived review.

**Identical to prior report lines 50–53.** No mitigation added.

---

### NIT — Line 174: Plan text contradicts its own code block

**Location:** Design line 174 vs. code block lines 103–112  
**Standard violated:** §3 Anti-Weeds (consistency)

Text: "Remove the `config.database = db or ""` assignment for Cases B and C" — but code passes `database=db or ""` to `Config(...)` constructor and never removes it.

**Identical to prior report lines 56–59.** No mitigation added.

---

### NIT — Unaddressed: Nonexistent `--db` path creates empty SQLite file

**Location:** Design line 124: `with Inventory(db) as prod_inventory`  
**Standard violated:** §1 Root Problem Focus / §2 YAGNI

`Inventory.__init__` (`inventory.py:76–82`) calls `sqlite3.connect(self.path)` + `executescript(_SCHEMA)`, creating the file if missing. `certclock check --db /new/prod.db --host …` writes empty `prod.db` even though nothing ingested. Acceptance criteria 1–3 (lines 59–62) only assert "mtime/size unchanged" for *existing* DB.

**Identical to prior report lines 62–65.** No mitigation added.

---

### NIT — Line 279: Promised test update not present

**Location:** Design line 279  
**Standard violated:** §0 Context Sufficiency (acceptance evidence)

Plan says "add assertion that demo DB file size/mtime unchanged after `check` call" for `test_check_against_existing_db_with_markdown`. Current test (`test_check.py:89–97`) only checks Markdown output. This is the only acceptance evidence for criteria 1–3.

**Identical to prior report lines 68–71.** No mitigation added.

---

## Summary Table

| Standard Clause | Prior Report | Current State |
|---|---|---|
| §0 Context Sufficiency | Pass | Pass (but test evidence missing) |
| §1 Root Problem Focus | Pass | Pass (architecture sound) |
| §2 Simplicity / YAGNI | Pass | Pass (no speculative features) |
| §3 Anti-Weeds / Altitude Control | **Fail (Nit)** | **Fail (Nit)** — unchanged |
| §4 Leverage Existing | **Fail (Blocker)** | **Fail (Blocker)** — unchanged |

---

## Required Fix (same as prior report)

Replace direct `Report(...)` construction in Case B with:

```python
# Merge StoredCert lists, dedupe by fingerprint
all_stored = prod_certs + temp_certs
seen = set()
deduped = []
for c in all_stored:
    if c.fingerprint not in seen:
        seen.add(c.fingerprint)
        deduped.append(c)

# Reuse existing pipeline
rules = load_owners(config.resolve(config.owners_file)) if config.owners_file else {}
owned = assign_owners(deduped, rules)
explained = explain(owned, now, weak_rsa_bits=config.weak_rsa_bits, 
                    max_validity_days=config.max_validity_days)
report = Report(
    generated_at=now,
    certificates=explained,
    gaps=prod_gaps + temp_gaps,  # gaps/warnings are strings, safe to concat
    warnings=prod_warnings + temp_warnings,
    horizon_days=config.horizon_days,
    warn_days=config.warn_days,
    crit_days=config.crit_days,
    notify_within_days=config.notify_within_days,
)
```

Also add guard for nonexistent `--db` in Case B (check `Path(db).exists()` before opening), and update the existing test as promised.

---

**No additions or mitigations have been made since the prior review.** The document is in the same state that produced the Blockers and Majors above.

