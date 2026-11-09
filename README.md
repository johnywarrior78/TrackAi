# AI Vulnerability Intelligence

A local, evidence-first Python platform for historical AI vulnerability intelligence and scheduled Excel reports. PostgreSQL is the deployment database; SQLite is an evaluation option. No LLM, paid API, or cloud account is needed.

> First released on September 25, 2025. This version is a new iteration of that release.

**Release status:** working initial implementation, validated on SQLite and a temporary PostgreSQL instance. This is not a claim that every item in the original production specification has been completed. See [validation and remaining gaps](docs/validation.md) before deployment.

## Native Linux

[Always-running Linux services guide](https://johnywarrior78.github.io/TrackAi/) — commands for starting the daily collector and local dashboard at boot. Also available [in this repository](docs/services.md).

```bash
./scripts/setup_linux.sh
./scripts/aivi dashboard
```

Supports glibc 2.28+ Linux on x86_64/ARM64. See [Linux installation](docs/linux.md).

## First-run historical population

Native setup and normal dashboard/scheduler startup automatically run a resumable historical initialization. The official CVE corpus is scanned across **all years**, alongside the available Anthropic history. A supported finding published in May 2025 remains visible when you install today: its source publication date is preserved, while first seen records today's actual observation. No last-30-days cutoff applies. [Historical initialization and coverage](docs/history.md) explains source limits, baseline reports, download size and resuming after interruption.

```bash
./scripts/aivi initialize
```

For offline development/CI, installers accept `--dev --skip-backfill` and dashboard accepts `--skip-backfill`. `aivi init-db` remains schema-only.

## Native macOS

Run from this project directory:

```bash
./scripts/setup_macos.sh
./scripts/aivi dashboard
```

Setup installs persistent project-local Python and the locked dependencies, then initializes and historically populates the configured database. After setup, **Start Dashboard.command** also launches the dashboard from Finder. Requires macOS 12+ and either `uv` or an existing `python3` with venv/pip support; Homebrew and Docker are optional. [Native macOS instructions](docs/macos.md) cover PostgreSQL, scheduling, alternate ports and startup verification. Apple Silicon is locally verified; Intel compatibility is not hardware-tested.

## Quick start (Python 3.12+)

From the repository root:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install uv==0.9.7
uv sync --frozen --extra dev
# Default DATABASE_URL is sqlite:///aivi.db (evaluation only).
aivi initialize
aivi dashboard
```

Open [the local dashboard](http://127.0.0.1:8501). Run commands in a second terminal while the dashboard is active. The included `aivi.db` and reports, when present in this workspace, are actual public-source validation artifacts; application installation does not seed synthetic findings. Tests create separate disposable databases.

For a new PostgreSQL deployment:

```bash
cp .env.example .env
# Edit DATABASE_URL and POSTGRES_PASSWORD; use a dedicated local database.
aivi initialize
aivi scheduler
```

Schedules use **UTC**, default 07:00 daily. They do not follow Lisbon daylight saving time. The scheduler first ensures historical initialization is complete, then schedules incremental daily cycles.

## Docker Compose

Requires Docker Engine and Compose v2. Choose a strong password without URL-reserved characters, or percent-encode it in a separately supplied DATABASE_URL. Do not commit `.env`.

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD in .env.
docker compose up -d --build
docker compose run --rm worker aivi backfill
docker compose run --rm worker aivi report
docker compose logs -f worker
```

Compose runs migrations and a resumable historical bootstrap service before launching the worker and dashboard. Database/report/log volumes survive container restarts. PostgreSQL has no published host port. The dashboard binds to host loopback. The worker health check checks process liveness; `aivi health` checks database connectivity and collection freshness separately. Docker configuration has not been executed on the development host because Docker is unavailable there.

## What is implemented

- Configurable source adapter contract; pooled HTTPS, bounded responses, timeouts, paced requests, retries/jitter, rate-limit accounting, allowlisted public hosts, no redirects.
- Anthropic's public ledger, structured payload, two published historical snapshots, sealed commitments stored independently, multiple assessor severities and snapshot provenance.
- Official CVE JSON enrichment and automatic resumable all-year cvelistV5 credit discovery, including rejected records and explicit unavailable-public-record observations.
- Credential-free GitHub Security Advisories API enrichment, optional token; KEV status transitions and dated EPSS history, including selective date backfill and official cached bulk CSV ingestion.
- SQLAlchemy persistence, Alembic schema, explicit identifier correlation and cluster merging; source-owned current facts, append-only source revisions and change events; real observed daily metrics.
- A seven-page Streamlit dashboard with search, page filters, sortable tables, evidence/details, history, health, CSV export, Excel generation and report downloads.
- Eight-sheet XLSX workbooks: baseline, incremental and custom exports; independent successful report checkpoints, atomic writes, formula protection, formatting, sheet splitting and long-text continuations.
- Transparent YAML remediation priorities, distinct from CVSS; unknown values remain null.
- Daily UTC scheduling, database job locks, structured rotating logs, health and attribution audit commands.

The read model uses the highest published severity assessment for filtering and clearly preserves the separate assessments in details. A high Claude assessment does not become an official CVSS score. EPSS averages exclude absent scores.

## Commands

```bash
aivi --help
aivi init-db
aivi initialize                     # automatic first-run historical population
aivi backfill                       # source-supported historical collection
aivi backfill --source anthropic
aivi sync                           # source failures isolated; exits 1 on partial/failure
aivi sync --source cve
aivi sync --source ghsa
aivi refresh-epss
aivi refresh-epss --start 2026-10-01 --end 2026-10-03
aivi refresh-kev
aivi report                         # daily; first successful report is BASELINE
aivi report --start 2026-10-01 --end 2026-11-01  # first-seen UTC [start,end)
aivi scheduler
aivi dashboard
aivi check-sources --source anthropic
aivi health
aivi verify-attribution
```

For an optional local CVE corpus override, obtain a permitted local checkout of [cvelistV5](https://github.com/CVEProject/cvelistV5), set `CVE_REPO_PATH` to its repository root, then run `aivi backfill --source cve`. This scans JSON files one at a time and checkpoints batch positions. Matching organization credits create **credited-only**, not confirmed AI discoveries. Update the checkout separately. The daily targeted refresher does not itself discover all newly published CVEs globally after initialization.

## Tests and dependency checks

```bash
uv sync --frozen --extra dev
uv run pytest -q
uv run ruff check app tests --select F
uv run pip-audit
# ONLY a dedicated disposable test database: fixtures create/drop application tables.
TEST_DATABASE_URL=postgresql+psycopg://test:password@localhost:5432/aivi_test uv run pytest -q
```

All external services in unit tests are mocked. Synthetic identifiers use the clearly labeled TEST fixtures and are never seeded into the application database. A real-source smoke test is an explicit CLI invocation, not part of default offline tests.

## Evidence and counting rules

A CVE and GHSA linked by an authoritative record identify one tracked finding. Shared titles, vendors and products never establish identity. Sealed commitments are source records with no vulnerability ID. Public identifiers are retained even if their official CVE record is not yet available, with that limitation recorded.

Confirmed AI use and confirmed discovery method are separate facts. Anthropic's program statement establishes AI use for its ledger, but human triage does not establish autonomous versus human-assisted discovery, nor an individual model. Those method/model fields remain unknown unless specific evidence supports them. Organization affiliation by itself establishes neither AI use nor autonomy. Withdrawn/rejected findings remain in the historical inventory with their state visible; inventory totals include them.

`daily_metrics` records actual platform observations only. An archived source snapshot date is not the platform's first-seen date. Source dates remain exactly represented as dates/ISO strings; platform event timestamps are timezone-aware UTC. Date-only publication values are not fabricated midnight event times.

## Documentation

- [Installation](docs/installation.md)
- [Native Linux installation](docs/linux.md)
- [First-run historical population](docs/history.md)
- [Native macOS setup](docs/macos.md)
- [Source status, access and licensing](docs/sources.md)
- [Architecture and data model](docs/architecture.md)
- [Operations](docs/operations.md)
- [Threat model and deployment security](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Executed validation and limitations](docs/validation.md)

Code is Apache-2.0 licensed. Source intelligence keeps its source's terms; the application license does not relicense collected material. Use local reports in accordance with those terms. No tracker content with unclear reuse permission is bundled.
