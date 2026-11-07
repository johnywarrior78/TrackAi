# Native Linux installation

Supported target: glibc 2.28+ distributions on x86_64 or ARM64 (aarch64), including Ubuntu 22.04+, Debian 12+, Fedora and RHEL 9+. Python and dependencies run directly on Linux. Docker is optional. Alpine/musl native installation is not supported by the locked PyArrow wheel; the supplied Debian-based Docker image is an alternative.

Clone the repository and run:

```bash
git clone https://github.com/johnywarrior78/TrackAi.git
cd TrackAi
./scripts/setup_linux.sh
./scripts/aivi dashboard
```

Open `http://127.0.0.1:8501` locally. On a remote Linux host use an SSH tunnel, for example `ssh -L 8501:127.0.0.1:8501 USER@HOST`. The dashboard stays on loopback by default.

The installer needs `uv` or a Python 3 installation with venv/pip support. It installs project-local Python 3.12.12 and locked dependencies; it does not replace the distribution's Python. If prerequisites are missing on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv ca-certificates libstdc++6
```

No sudo is used by the project installer. Run it as the ordinary user who will operate the app. Runtime/dependencies are stored in `.python`, `.venv`, `.bootstrap` and `.cache`. The script works with spaces in the project path. After moving the directory, rerun setup to recreate absolute virtual-environment paths.

## First-run population

**Default setup runs `aivi initialize`: migrations, historical collection from all available years, and a baseline report.** It downloads a pinned compressed snapshot of the official CVE corpus, scans it in batches and retains records with monitored AI-organization credits or explicit tracked identifier relationships. No installation-date, release-date, year or last-30-days cutoff is applied. It also imports the available Anthropic history and enriches against GitHub/KEV/EPSS.

The initial CVE download can be hundreds of megabytes and the scan can take several minutes; reserve a few GB of free space. Only the compressed archive is cached, and member files are read without extraction. Progress is logged every batch; checkpoints survive restart. Rerun `./scripts/aivi initialize` after an interruption. Missing/unavailable sources leave initialization incomplete rather than declaring an empty inventory successful. Some GitHub enrichment may remain queued under public API quotas even after the historical inventory is populated.

The default database is SQLite for evaluation; configure PostgreSQL in `.env` for deployment before running setup. Existing `.env` and databases are preserved. See [historical initialization](history.md) for date semantics and coverage limitations.

## Offline development and validation

To install without downloading source intelligence:

```bash
./scripts/setup_linux.sh --dev --skip-backfill
.venv/bin/python -m pytest -q
.venv/bin/python scripts/smoke_native.py
./scripts/aivi dashboard --skip-backfill
```

`--skip-backfill` is an explicit opt-out for that invocation, not a completed historical initialization. Normal dashboard/scheduler startup retries initialization unless `AUTO_BACKFILL=false` is configured. `aivi init-db` always remains a schema-only command.

## PostgreSQL and services

Install and start PostgreSQL using your distribution's supported packages. Create a dedicated role/database, set `DATABASE_URL=postgresql+psycopg://USER:URL_ENCODED_PASSWORD@localhost:5432/aivi` in `.env`, then run `./scripts/aivi initialize`. Switching databases does not migrate the SQLite inventory automatically.

Run `./scripts/aivi scheduler` in a long-lived process or systemd service using the absolute launcher path. Its working directory is anchored by the launcher. The initial historical population happens immediately before scheduling; subsequent scheduled cycles are incremental. All schedules use UTC. For authenticated multiuser access use the reverse-proxy/TLS guidance in [security.md](security.md).
