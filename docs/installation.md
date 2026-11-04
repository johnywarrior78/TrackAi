# Installation

For macOS, use the [native setup and launchers](macos.md); they install a persistent project-local Python runtime and handle working directories containing spaces.

Use Python 3.12 or newer. Supported deployment database: PostgreSQL 17 (16+ should work but must be validated for your deployment). Install dependencies using `uv sync --frozen`; `uv.lock` locks direct and transitive packages. `pyproject.toml` is the package manifest. The project root must be the working directory for CLI commands, migrations and configuration.

The `.env.example` lists all common settings. Pydantic reads `.env`, with environment variables taking precedence. `DATABASE_URL` defaults to `sqlite:///aivi.db` for a zero-credential local evaluation. Copying `.env.example` switches to PostgreSQL. Run `aivi init-db` after changing databases; this does not copy data across engines.

Use a dedicated PostgreSQL database and role with schema creation privileges for initial migration, then restrict deployment roles as appropriate. The migration command uses the same DATABASE_URL as the application. PostgreSQL connection URLs use the psycopg driver: `postgresql+psycopg://...`.

Other settings:

| Variable | Default | Purpose |
|---|---|---|
| REPORT_DIR | reports | XLSX output, owner-only files |
| LOG_DIR | logs | Structured console + rotating files |
| SCHEDULE_HOUR / SCHEDULE_MINUTE | 7 / 0 | Daily UTC cron trigger |
| HTTP_TIMEOUT | 30 | Per-request seconds |
| HTTP_RETRIES | 4 | Retry budget |
| REQUEST_INTERVAL | 1 | Minimum seconds between source requests |
| GITHUB_TOKEN | empty | Optional higher GitHub API quota; never required for public mode |
| ENRICHMENT_LIMIT | 500 | Maximum tracked CVEs per CVE/GHSA sweep invocation |
| EPSS_BULK_THRESHOLD | 1000 | Switch to FIRST-linked cached bulk CSV |
| CACHE_DIR | .cache | Local dated EPSS bulk file cache |
| CVE_REPO_PATH | empty | Local cvelistV5 repository for historical credit search |
| ANTHROPIC_SNAPSHOTS | 2026-05-22-1027,2026-08-26-1155 | Published snapshots visited on backfill |
| PRIORITY_CONFIG | config/priority.yml | Transparent operational rules |

Scheduler settings use UTC throughout. Start the dashboard with `aivi dashboard`, which binds localhost. For a container or reverse proxy, invoke Streamlit directly using a chosen bind address. Do not expose it to untrusted networks without authentication and TLS.

Run `aivi init-db`, `aivi backfill`, then `aivi report`. A source outage may cause backfill to exit nonzero while other sources succeed; rerun after examining Source Health. Review `aivi health` rather than assuming a zero-exit scheduler implies complete data.
