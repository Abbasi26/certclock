# Stage 5: Initial Zoom Out Review
### Reviewer: egm-zoom-out (Modell: `kilo/kilo-auto/free`, frischer Prozess)



Let me verify the design's claims against the actual codebase.
I have everything I need. Here are the findings.

## Review: `2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md` vs Zoom-Out Standard

**Verdict: Conditional pass — the goal is right, but the Detailed Implementation Plan (lines 141–157) is functionally broken as written and must be corrected before implementation.**

---

### BLOCKER — Design line 147–156: merged `Report` is constructed from `StoredCert` objects and skips `explain()` entirely

The plan collects `prod_certs` / `temp_certs` via `Inventory.certificates()`, which returns `list[StoredCert]` (`inventory.py:144`). It then concatenates them and passes the result into `Report(certificates=all_certs, …)` at design line 147. But `Report.certificates` is typed `list[ReportCert]` (`models.py:137`), and `StoredCert` (`models.py:70`) is a **different dataclass** — it has no `days_remaining`, `bucket`, `problems`, `owner`, `service`, `dependency_note`, or `sources` fields.

Consequences, all visible in the code that the design would produce:
- `evaluate()` (`check.py:51`) calls `status_code(cert, …)` → `cert.days_remaining` → `AttributeError` on every cert.
- `render_text` (`check.py:113–120`) reads `cert.sources` and `cert.problems` → `AttributeError`.
- `render_json_outcome` (`check.py:151, 161`) reads `cert.sources`, `cert.problems` → `AttributeError`.

So Case B (`--db` + `--host`/`--path`) crashes. This is not a hypothetical: every field the report pipeline touches after construction is missing.

**Rationale:** The design's own step 4 (line 178–185) only checks that the `Report` *dataclass fields* match the constructor call — it never checks the element type. The standard's §4 (Leverage Existing) is also violated here: rather than reusing the existing `build_report`/`explain` pipeline (`pipeline.py:54–76`, `explain.py:287–419`), the plan reinvents report construction inline, which is exactly how the type error was introduced.

**Required fix:** Merge the two `StoredCert` lists, dedupe by fingerprint, then run `explain(merged_stored, now, weak_rsa_bits=…, max_validity_days=…, owners=assign_owners(merged_stored, rules))` and pass the resulting `ReportCert` list to `Report(...)`. This is one line change from "construct Report directly" to "call the existing helper" and also fixes the next two findings.

---

### BLOCKER (closely related) — Design lines 147, 174: owner rules are never applied in Case B

`build_report` (`pipeline.py:56–58`) loads the owners file via `config.resolve(config.owners_file)` and passes `assign_owners(stored, rules)` into `explain()`. The plan's Case B constructs `Report` directly and never calls `load_owners`/`assign_owners`. So `check --db prod.db --host … --owners owners.yml` would silently stop assigning owners/service/notes — a behaviour regression vs. the existing single-DB path, and a direct contradiction of Non-Goal "no other behaviour changes" (line 14). `Config(owners_file=owners, …)` at design line 103–112 sets the field but nothing reads it in Case B.

---

### MAJOR — Design lines 142–144: no deduplication of certificates across the two inventories

`all_certs = prod_certs + temp_certs` can contain the same fingerprint twice. The production DB dedupes by SHA-256 fingerprint, but the merge has no such step. Concrete trigger: `certclock collect files --db prod.db --path /etc/ssl/certs/app.pem`, then `certclock check --db prod.db --path /etc/ssl/certs/app.pem` — the same DER is read again, appears in both lists, and is counted twice in `report.summary()` and listed twice. The design's risk table (lines 49–55) and tests (lines 250–268) do not cover this. Dedupe by fingerprint before passing to `explain()`.

---

### MAJOR — Design lines 146–157: cross-inventory dependency analysis is lost even if `explain()` were added per-inventory

`explain()` (`explain.py:297`) indexes *all* passed certs together for `_choose_issuer` / `_chain_includes_issuer`. If the plan were "fixed" by calling `explain()` on each list separately and concatenating `ReportCert` rows, a leaf collected ad hoc whose issuer lives only in the production DB would be wrongly flagged `issuer_not_in_inventory` (`explain.py:347–355`) and would lose its `issuer_expires_first` finding. The correct merge must feed the *combined* `StoredCert` list into a single `explain()` call — which is exactly why the Blocker fix above is the right shape.

---

### NIT — Design lines 84–170: implementation plan violates Standard §3 (Anti-Weeds / Premature Detail)

The "Detailed Implementation Plan" section contains a full refactored `run_check` source listing, five inline pytest functions (lines 200–276), and per-step commentary. The standard says high-level sections must focus on architecture, interfaces, and data flows, not code-level details. The "Proposed Architecture" section (lines 22–47) is at the right altitude; the plan section should reference it rather than re-derive it. This is not just style — it is where the three errors above survived review, because the code was treated as specification rather than as an illustration.

---

### NIT — Design line 174: plan text contradicts its own code block

The text says "Remove the `config.database = db or ""` assignment for Cases B and C", but the code block at lines 103–112 passes `database=db or ""` directly to the `Config(...)` constructor and never removes it. Cosmetic, but it is the kind of drift that erodes trust in the rest of the listing.

---

### NIT — Unaddressed: nonexistent `--db` path leaves an empty SQLite file

In Case B, `with Inventory(db) as prod_inventory` (`inventory.py:76–82`) calls `sqlite3.connect(self.path)` and `executescript(_SCHEMA)`, which **creates** the file if it does not exist. So `certclock check --db /new/prod.db --host …` writes an empty `prod.db` to disk even though nothing is ingested into it. Acceptance criteria 1–3 (lines 59–62) only assert "mtime and size unchanged" for an *existing* DB. Worth an explicit criterion or a guard.

---

### NIT — Design line 279: the promised test update is not yet present

The plan says "add assertion that the demo DB file size/mtime is unchanged after the `check` call" for `test_check_against_existing_db_with_markdown`. The current test (`test_check.py:89–97`) only checks the Markdown output text, not DB immutability. Planned, not a defect — but it is the only acceptance evidence for criteria 1–3 and is currently absent.

---

### Standard compliance summary

| Standard clause | Result |
|---|---|
| §0 Context Sufficiency | Pass — problem, goals, non-goals, alternatives, risks, acceptance criteria all present |
| §1 Root Problem Focus | Pass — solves the root cause (never write to the production DB), aligns with README's read-only philosophy |
| §2 Simplicity / YAGNI | Pass — merge-in-memory, no speculative features |
| §3 Anti-Weeds / Altitude Control | **Fail (Nit)** — code-level detail in the implementation plan; the code listing became the spec |
| §4 Leverage Existing | **Fail (Blocker)** — bypasses `build_report`/`explain`/`assign_owners` instead of reusing them, which is the direct cause of the Blocker |

**Bottom line:** The architecture is sound and matches the codebase's existing temp-DB pattern. Do not implement from lines 141–157 as written. Replace the direct `Report(...)` construction with a deduplicated `StoredCert` merge fed through the existing `explain()` + `assign_owners` pipeline, then re-check the four code paths (A: db-only, B: db+ad-hoc, C: no-db, plus the nonexistent-db edge case).

