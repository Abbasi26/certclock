# Design decisions

## 2026-11-03: `check --db` Opens the Database Read-Only

**Design:** [2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md](2026-11-03-check-db-oeffnet-die-datenbank-nur-lesen.md)

### Decisions

1. **Read-only enforcement by convention, not mechanism**: The production database is opened normally (`Inventory(db)`) but `ingest()` is never called. A true SQLite read-only URI was rejected because `Inventory.__init__` runs `executescript(_SCHEMA)` which fails on a read-only connection. The "no writes" guarantee rests on restraint, documented as an accepted risk (future `Inventory` changes could silently write).

2. **Merge via single `explain()` on combined `StoredCert` list**: Case B merges production and ad-hoc certificates at the `StoredCert` level, deduplicates by SHA-256 fingerprint, then feeds the combined list through `explain()` with `assign_owners()` and threshold parameters (`weak_rsa_bits`, `max_validity_days`). This preserves cross-inventory issuer matching (e.g., leaf in temp DB with issuer only in prod DB) and reuses the existing pipeline.

3. **Owner assignment preserved in merged report**: The `--owners` file is loaded and `assign_owners()` applied to the merged `StoredCert` list before `explain()`, ensuring `check --db prod.db --host … --owners owners.yml` produces owned reports — no regression vs. single-DB path.

4. **Thresholds (`weak_rsa_bits`, `max_validity_days`) active in all cases**: By routing Case B through `explain()`, the configured thresholds take effect for `weak_key` and `long_validity` findings, closing the Case B gap.

5. **Deduplication by fingerprint before `explain()`**: Merged `StoredCert` list is deduped by `fingerprint` to prevent double-counting in `Report.summary()` and duplicate listings when the same cert exists in both DBs (common case: scheduled `collect` then ad-hoc `check --path`).

6. **Config construction moved inside case branches**: `Config` creation is deferred until after the case split so Case B/C can omit the `database` field (or pass `""`) since they construct `Report` directly without `build_report`.

7. **Acceptance criteria measure file invariance, not open mode**: Criteria assert production DB `mtime`/`size` unchanged — a behavioural check. No criterion verifies read-only open mode (e.g., `PRAGMA query_only`). This is a known gap; the design accepts the weaker invariant.

8. **CHANGELOG entry under `## Unreleased`**: Matches existing project convention (no `## Fixed` section).

9. **Error behaviour for unreadable `--db` corrected**: Documented exception type is `sqlite3.OperationalError` (not `OSError`); `_cmd_check` catches `Exception` so exit 3 is preserved.

### Consciously Rejected Findings

- **Read-only SQLite URI (Alternatives table)**: Rejected because `Inventory.__init__` calls `executescript(_SCHEMA)` which fails on read-only connection. The design accepts "open normally, never call `ingest`" as the enforceable convention.

- **Copy production DB to temp, ingest into copy**: Rejected — extra I/O and disk usage; production DB can be large. In-memory merge is more efficient.

- **Add `--read-only` flag**: Rejected — CLI already promises read-only semantics for `--db`; adding a flag admits current behaviour is wrong.

- **Make `Inventory.ingest` a no-op with `read_only` flag**: Rejected — requires threading flag through `CollectionResult`, `Inventory`, and all callers (`scan`, `collect`, `import`). Scope creep.

- **Per-inventory `explain()` then concatenate `ReportCert` rows**: Rejected — loses cross-inventory dependency analysis (issuer in prod DB, leaf in temp DB would be wrongly flagged `issuer_not_in_inventory`). Single `explain()` on combined list is required.

- **Contested items from egm-codebase-details (CD-02 through CD-12)**: These were clarifications or verified-correct items (imports present, helpers defined, exception handling correct), not design defects. No action taken.