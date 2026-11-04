# Architecture

The CLI, scheduler and dashboard share the same settings, database, read model and report generator. Adapters yield normalized `Record` objects in `Page`s. A page transaction persists identifiers, facts, source revisions and its checkpoint together. A failed page rolls back; prior pages remain committed. A failed adapter is isolated from subsequent sources in a cycle.

## Persistence model

- `vulnerabilities`: internal finding identity, canonical text/dates/state and UTC observation/enrichment timestamps.
- `vulnerability_identifiers`: globally unique normalized CVE/GHSA values and foreign keys.
- `sources`, `collection_runs`: checkpoints, health, execution counters and errors.
- `source_records`: latest public source object, unique `(source,key)`; unrevealed commitments have no finding FK.
- `source_snapshots`: immutable public payload revisions observed by the platform. Digest includes normalized projection so a parser correction can update existing data idempotently.
- `vulnerability_facts`: source-owned typed facts, unique `(finding,source,kind,key)`. Kinds are product, severity, attribution, classification, reference, remediation, availability, snapshot, KEV and EPSS.
- `vulnerability_change_events`: previous/current canonical and fact values, including removals and explicit cluster merges. KEV transitions remain here as well as in source snapshots.
- `epss_history`: dated probabilities/percentiles with unique `(CVE,date)`.
- `daily_metrics`: actual daily aggregate observations, never reconstructed from present state.
- `report_runs`: independent successful report cutoffs, baseline/custom flags and artifact paths.
- `job_locks`: fail-closed SQLite evaluation locks. PostgreSQL uses connection-scoped advisory locks instead.

Products, versions, attribution evidence and severity are typed JSON fact documents rather than separate organization/product lookup tables. This keeps conflicting source representations intact and avoids pretending their semantics are identical. Foreign keys and unique constraints protect ownership and identity; indexes cover identifiers, finding fact lookups and change dates. Additional dedicated dimensions and JSON indexes should follow measured query needs. This is an explicit deviation from the recommended fully normalized entity list.

## Correlation

Only explicit public identifier relationships merge clusters. The lowest internal ID survives. Identifier, source record, fact, score-history and change ownership moves to it; a merge event records the operation. Duplicate fact ownership is reconciled while immutable source snapshots preserve the underlying values. Erroneously corrected identifiers in Anthropic data are excluded from new alias relationships; previously accepted relationships are not automatically split later, since undoing a cluster merge requires careful review.

Canonical CVE text has preference when available. Source-owned severity assessments never replace one another. Published/discovered source fields remain separate from first/last observation. The dashboard's maximum-assessment severity is a display policy, not an authoritative consensus.

## Reporting correctness

The report lock prevents overlapping reports. The collection lock prevents source changes during report generation. The cutoff is recorded only as a successful daily checkpoint after atomic file replacement and database commit. Failure leaves prior successful cutoff untouched; an orphan file after process death can be reviewed without losing collection data. Custom exports never become daily checkpoints. A baseline's New/Updated sheets are empty; inventory sheets still show current findings.

New rows are first observed after the prior successful report and before the cutoff. Updated rows are change events on findings that existed at the checkpoint. Updated worksheet grain is **change event**, with repeated finding IDs deliberately representing different field changes. Other finding sheets are one row per correlated finding. A first-seen custom range governs inventory sheets; the Updated sheet represents existing-finding changes in that interval.

Workbook serialization uses write-only worksheets and batches database reads. Summary grouping uses in-memory sets keyed by finding, product and organization; very large inventories may require SQL aggregation. Excel's row limit splits worksheets; long strings move losslessly to numbered `Long Text` continuation rows. Formula-like strings become explicit text and are neutralized for downstream spreadsheet handling.

## Scheduling and concurrency

One scheduler owns a database-wide scheduler lock for its lifetime. Collection/report jobs are serialized independently. PostgreSQL advisory locks auto-release on connection/process death, with no expiring lease overlap. SQLite stale locks need explicit operator recovery. A manual collection can interleave between sources in a scheduled cycle; each source transaction and report remains consistent.
