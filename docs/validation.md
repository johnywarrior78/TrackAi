# Executed validation and remaining gaps

Validation date: **2026-11-03 UTC**. Runtime: Python **3.12.12**, macOS arm64. These are executed results, not claims of untested production readiness.

## Automated checks

- **49 tests passed on SQLite**: identifier validation, CVE/GHSA bridge merges, title noncorrelation, attribution evidence requirements, affiliation-only/unknown claims, unrevealed/revealed ledger handling, assessor separation, corrected identifiers, CVSS bounds, EPSS historical ordering/cache/filtering, KEV transitions, page rollback/recovery, repeated-ingestion idempotency, source isolation, report baseline/new/updated/custom/checkpoint behavior, failed-report recovery, empty workbooks, formula/control-character handling, long-text continuation, sheet splitting, SSRF URL rejection, rate-limit retry, job locking and all seven dashboard pages.
- The same suite runs against a **temporary real PostgreSQL server** using an isolated database (see final execution record below). PostgreSQL advisory locking and JSON query expressions were exercised.
- Alembic initial schema upgrade, metadata drift check, downgrade to base and second upgrade succeeded on PostgreSQL. The initial migration contains explicit immutable schema operations.
- Ruff undefined/unused-name checks passed (`ruff check app tests --select F`).
- `pip-audit` on the locked application/development environment reported **no known vulnerabilities** after patched dependency updates. Advisory databases can change; rerun for deployment.
- Streamlit AppTest executed all seven pages both on an empty isolated database and manually against the collected real database without exceptions.

## Real public integrations

- Current Anthropic source: **6,597** ledger entries; **237** revealed entries correlated to **232 unique internal findings** through public identifier relationships. Unrevealed entries were retained with null vulnerability IDs.
- Public historical snapshots dated **2026-05-22-1027** and **2026-08-26-1155**, then current **2026-10-02**, successfully ingested using directly linked ledger/payload JSON. All source observations retain the actual local observation date.
- Repeating the current Anthropic run after backfill processed **6,597 records, created 0, updated 0**.
- Local inventory holds **102 distinct CVE identifiers** and **169 distinct GHSA identifiers**. These counts are not interchangeable with vulnerability counts or the source's headline disclosure totals.
- Official CVE JSON was retrieved for tracked IDs. **Four** identifiers lacked public cvelistV5 records during validation; these have explicit availability observations. A 404 no longer prevents later IDs from being enriched. All identifiers remain subject to authoritative verification.
- GitHub advisories were retrieved successfully without credentials for sampled tracked CVEs. This was a bounded partial sweep, not full GHSA coverage. Resumable direct GHSA lookup is implemented as well; that path has not been comprehensively tested against all live IDs.
- CISA's full current KEV catalog was retrieved and joined against the **102** tracked CVEs. No tracked KEV matches were observed in this particular inventory; this is not a claim that no AI-discovered vulnerabilities are exploited.
- FIRST EPSS API returned **96** scored tracked CVEs for **2026-11-02**. The FIRST-linked official dated gzip CSV archive was also retrieved, filtered and ingested successfully; current scores and **96 historical points** were retained without duplicate `(CVE,date)` rows.
- A complete bounded five-source cycle succeeded and recorded an actual daily aggregate observation.
- Real XLSX baseline, incremental and custom inventory reports were generated and reopened with OpenPyXL. All eight required worksheets, frozen headers, filters and absence of executable formula cells were checked. The `custom` workbook's New sheet is explicitly a first-seen range export of inventory, not 232 discoveries on the report date.

Source URLs, access/licensing caveats and coverage distinctions are in [sources.md](sources.md). No synthetic findings were inserted into the real evaluation database.

## Material gaps / known limitations

1. **Not all requested production functionality is complete.** The current implementation is a working initial application with real ingestion, persistence, reporting and dashboard, not an independently audited production release.
2. **Interactive filters/charts apply to a 500-row result page**, explicitly labeled in the UI. Global identity KPIs use database counts, while the other filtered KPIs/charts use that result page. Publication/discovery/first-seen date filtering now runs in SQL before pagination. Other database-wide filtering/aggregation, filtered full-inventory export and keyset pagination remain work for large deployments. Reports batch through the full matching first-seen inventory.
3. Provider discovery is currently Anthropic-ledger led. The official full CVE corpus is now downloaded/scanned automatically on first run for conservative monitored-organization CNA/ADP credit discovery; local checkout remains an override. **Global CVE delta-feed discovery, automated primary-evidence review and dedicated OpenAI/DeepMind/Microsoft/DepthFirst disclosure adapters are not implemented.** No capability ranking is implied.
4. FIRST bulk processing is supported, but caches have no retention policy and current small-batch API lookups are not skipped solely because another same-day run occurred. Historical score methodology/model-version shifts are not yet represented as a separate dimension.
5. Historical analytics exposes actual daily inventory/confirmed counts, EPSS means and change events. Not all requested week/month comparisons, patch/CVSS/KEV trend charts or arbitrary source as-of reconstruction are implemented.
6. Fact documents preserve source products/versions, assessments and evidence using typed JSON rather than every recommended fully normalized entity table. Current facts have application validation rather than full upstream JSON-schema validation; source update timestamps remain in raw source snapshots, not a universal canonical column.
7. Erroneous identifiers corrected after a historical cluster merge require reviewed splitting; the application never guesses how to undo a prior merge. Withdrawal/rejection retains the finding in inventory, with its state exposed.
8. **Frontier tracker ingestion is disabled** because the public repository currently has no identified content license. No README findings table was copied into the application.
9. No native authentication, RBAC, asset exposure/business-criticality configuration or separately sourced public exploitation evidence is implemented. KEV, CVSS, EPSS and patch facts drive the current transparent priority engine. Apply authenticated TLS reverse proxy and deployment hardening for shared access.
10. Docker Compose/Dockerfile are supplied but **not built/run on this host**, which has no Docker executable. PostgreSQL was validated separately. A scheduled 24-hour timer was not left running; the collection/report components and locking were exercised directly. Native SQLite locks now auto-release on process exit.
11. Source pages are atomic: malformed records fail their current page and require source/schema correction. There is no dead-letter review queue. Enrichment sweeps may span several runs under configured/GitHub quotas; health shows this incompleteness.
12. The full cvelistV5 snapshot was scanned end-to-end on 2026-11-07 (420,768 records, 474 matched). Broader credit discovery quality and disclosures lacking public CVE credit still require curated evidence and additional official adapters. Summary grouping in reports still maintains per-product/provider sets in memory and should move to SQL for very large inventories.

## Recommended next work

Prioritize database-wide dashboard filters/aggregates and exports; verified primary-source attribution ingestion for the other monitored providers; automated CVE delta discovery; full as-of/time-range analytics; then hardened Docker deployment validation, separated database roles/authenticated access and performance/load testing. Keep unconfirmed attribution and unavailable enrichment explicit throughout.

## Final execution record

Final SQLite run: **49 passed**. Final temporary PostgreSQL run: **49 passed**. Immutable migration upgrade, drift check, downgrade and repeat upgrade all passed after the PostgreSQL NUL-text handling correction. Final Ruff checks passed. The current evaluation inventory has 232 unique findings, 102 CVEs, 169 GHSAs and one actual platform daily aggregate snapshot. The verified current real-data sample is `reports/AI_Vulnerability_Intelligence_2026-11-03_custom_4.xlsx` (eight worksheets, 232 inventory rows in its custom range sheet).

## Native macOS follow-up — 2026-11-04

- Executed the new native installer on **macOS 15.7.3, Apple Silicon arm64**. It installed persistent Python **3.12.12** under the project's `.python` directory and rebuilt `.venv` from the existing dependency lock. The old `/tmp` interpreter dependency has been removed from the primary application environment.
- **51 tests passed** on the rebuilt native environment, including launcher working-directory/argument handling and configurable dashboard port validation. Ruff and Bash syntax checks passed. Two existing Typer/Click deprecation warnings do not affect startup.
- The offline native smoke check passed: compiled pandas/psycopg/PyArrow imports, CLI invocation from a different directory, isolated database migrations, generation/reopening of an eight-sheet Excel baseline, and an actual localhost Streamlit HTTP health response. The test dashboard was shut down afterwards.
- Streamlit starts without an interactive first-run onboarding prompt; usage telemetry is disabled by the CLI launcher. The default bind remains localhost.
- Added executable `scripts/setup_macos.sh`, `scripts/aivi`, and `Start Dashboard.command`, plus a macOS CI job. The CI job was added but has not been remotely executed in this session. Intel Macs have not been hardware-tested.
- See [macOS instructions](macos.md). Existing platform scope limitations above remain applicable; this follow-up verifies native macOS installation/startup rather than completing those unrelated features.

## Linux and historical first-run follow-up — 2026-11-07

- Added native Linux setup (glibc 2.28+, x86_64/ARM64) and shared native bootstrap steps. The GitHub Linux job now runs that installer and the native startup smoke check, alongside its PostgreSQL suite. Initial source downloads are deliberately skipped in CI; fixture tests exercise initialization itself.
- Added schema revision 0002 and persistent initial population state. Native installers, normal dashboard startup, scheduler startup and Docker's bootstrap service populate history automatically; schema-only/offline opt-outs remain explicit.
- Live `aivi initialize` completed successfully against all five enabled sources. The pinned official CVE snapshot `f594d4fdde64803f0198cac426901616c7628633` downloaded as a ~209 MiB compressed archive and **420,768 CVE records** were streamed across all years. **474 records** matched monitored CNA/ADP credits or already tracked IDs; **375 new correlated findings** were created, bringing the local inventory to **607**. Its earliest currently matched publication is **2025-07-15**; no real May 2025 record is claimed by this validation.
- Regression fixtures explicitly verify a May 2025 record and a 2023 record imported into a fresh database today, without altering publication dates or fabricating discovery dates. A separate test places an older record beyond 500 recent rows and confirms SQL date filtering finds it before pagination.
- Repeated initialization returned the persisted successful state without another corpus download or scan. Interrupted batches resume from checkpoints. Empty/malformed source snapshots cannot silently mark historical initialization complete. Source outages leave initialization incomplete, while partial intelligence remains stored.
- Final local tests: **64 passed on SQLite**; **63 passed, one SQLite-specific test skipped on PostgreSQL**. The PostgreSQL migration upgrade/drift-check/downgrade/re-upgrade passed. Ruff, shell syntax checks and the real localhost dashboard/Excel native smoke check passed.
- Native SQLite now uses OS file locks (macOS/Linux). A subprocess termination test verifies crash recovery; the old SQL lock table remains only for migration compatibility.
- Initial historical inventory completion and optional enrichment are distinguished: the live GitHub advisory enrichment sweep remains pending under its public request budget. Source-supported credit matching is not a claim that every worldwide AI discovery has public CVE credit, and credited-only affiliation is not promoted to verified AI use.
