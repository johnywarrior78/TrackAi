# First-run historical inventory

The first native installation, normal dashboard launch or scheduler start runs `aivi initialize`. Docker Compose has a separate `bootstrap` service that completes historical inventory population before the dashboard and worker start.

Initialization is separate from the schema-only `aivi init-db`. `application_settings.initial_historical_backfill` stores its status. A database containing some rows is not assumed fully initialized. Successful historical CVE batches and source checkpoints are committed independently, so a retry resumes after an interruption. A successful initialization is remembered; normal subsequent starts do not repeatedly download and scan the entire corpus.

## Example: a May 2025 vulnerability

If a supported public record says it was published on **2025-05-12**, and the first local run is **2026-11-07**, the stored dates are:

- Publication date: **2025-05-12** (the date stated by the source).
- First seen by this platform: **2026-11-07 UTC** (actual observation).
- Discovery date: the source's discovery date, or **unknown** if none is published.

This older record appears in the explorer and publication-date filters. Those date filters execute in the database **before** pagination, so older records are not hidden merely because their internal IDs fall beyond the first 500 rows. No date filter is enabled by default. Other interactive filters still apply to the resulting page.

The first workbook is a labeled **baseline**. Historical inventory is not described as vulnerabilities newly discovered on the installation date, and historical daily snapshots/EPSS values are not invented. Selective real EPSS date backfill remains available separately.

## How the historical sources work

Anthropic imports its configured published snapshots plus the current public ledger/payload. Unrevealed ledger commitments remain separate from identified findings. Source dates and snapshot provenance remain distinct from local observation time.

For CVEs, initialization retrieves the current official cvelistV5 commit SHA and downloads its fixed `codeload.github.com/CVEProject/cvelistV5` tar snapshot. It scans **all years** in that corpus without a time cutoff. Records with monitored-organization credit in CNA/ADP containers, or identifiers already tracked by the platform, are retained. Unrelated CVEs are scanned but not copied into the application inventory. Organization affiliation remains **credited-only**, not confirmation that AI was used. Products merely mentioning an AI provider do not qualify as discovery credit.

Set `CVE_REPO_PATH` to an existing official checkout to scan it instead of downloading. Keep that checkout unchanged during a resumable scan. The default downloaded archive pins the revision until scanning finishes. Archive members are streamed without extracting paths to disk; downloads are bounded, partial downloads are retained and HTTP Range is used when supported. If the server ignores Range, the download restarts safely. Large archive downloads have a longer read timeout than small JSON requests.

This is the full **source-supported historical inventory**, not a guarantee of every AI-discovered bug worldwide. A finding with no public record, no public attribution/identifier relationship, or unavailable source cannot be reliably classified. The Frontier tracker remains excluded while its content licensing is unclear. No record is fabricated to fill a gap in coverage.

## Commands and controls

```bash
./scripts/aivi initialize          # first-run population; resumes if incomplete
./scripts/aivi backfill --source cve
./scripts/aivi sync                # later targeted incremental enrichment
./scripts/aivi health
```

`initialize --force` retries source collection after a previously completed initialization, retaining already-completed archive scan checkpoints. It does not erase history or fabricate older observations. Removing/rebuilding an archive checkpoint to rescan attribution rules should be a deliberate operator action.

- `AUTO_BACKFILL=true` is the default. Set false only for intentional offline/schema-only evaluation.
- `--skip-backfill` is available on native installers and dashboard startup for offline use/CI.
- `HISTORY_BATCH_SIZE=1000` controls atomic scan batches.
- `CVE_ARCHIVE_MAX_BYTES=2147483648` bounds the compressed download.
- `CACHE_DIR` locates cached source archives; Docker persists it in the `cache` volume.

A source outage keeps status incomplete and exits initialization nonzero, while already collected data is preserved. Limited GitHub enrichment can remain pending and is reported explicitly. Historical inventory completion does not imply all optional enrichment is available.
