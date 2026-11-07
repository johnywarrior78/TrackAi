# Native macOS setup

The app runs directly on macOS; Docker is optional. The native installer targets macOS 12 or newer on Apple Silicon (`arm64`) and Intel (`x86_64`), matching the locked binary dependency wheels. Apple Silicon is tested locally on macOS 15.7.3. Intel installation is supported by the installer and dependency lock but has not been tested on a physical Intel Mac.

## Install and start

In Terminal, change to the project directory (quote the path because it contains spaces):

```bash
cd "/path/to/ai-vulnerability-intelligence"
./scripts/setup_macos.sh
./scripts/aivi dashboard
```

Open [the dashboard](http://127.0.0.1:8501). Stop it with Control-C. After setup, you can also double-click **Start Dashboard.command** in Finder. This launcher changes to the project directory, applies migrations and starts the dashboard. Normal setup and dashboard startup populate historical sources automatically on first use. See [historical initialization](history.md); the initial official CVE corpus download may be large.

Setup needs either an installed `uv` command or an existing `python3` with venv/pip support. If using Homebrew, `brew install uv` supplies that prerequisite. Otherwise the script uses `python3` to bootstrap the pinned uv version locally, then installs the Python version in `.python-version`. It never changes Apple's system Python. See [uv's Python installation documentation](https://docs.astral.sh/uv/guides/install-python/) for the managed runtime mechanism.

Python lives in **`.python/`**, dependencies in **`.venv/`**, optional bootstrap tooling in **`.bootstrap/`**, and downloads in **`.cache/uv/`**, all inside the project. Python is not stored in `/tmp`. Re-running setup recreates only `.venv` and applies database migrations; your database, `.env`, reports and collection history are retained. Stop running app processes before refreshing the environment. If you move the project folder, rerun setup before using it at the new location, because virtual environments contain absolute interpreter paths.

The default database is local SQLite for evaluation. An existing `.env` or exported DATABASE_URL takes precedence; if it selects PostgreSQL, start that database before setup. Setup does not create or overwrite `.env`. It does not transfer SQLite records to PostgreSQL.

## Collect, report and schedule

From the project directory:

```bash
./scripts/aivi backfill --source anthropic
./scripts/aivi sync
./scripts/aivi report
./scripts/aivi scheduler
```

Use separate Terminal windows for the dashboard and scheduler. Scheduling is UTC (07:00 by default), including when Lisbon switches daylight saving time. The native worker runs while its process is alive and the Mac is awake; sleeping the Mac or closing its Terminal interrupts normal operation. For unattended service operation, configure a launchd job with an absolute `scripts/aivi` path and `scheduler` argument, or run the deployment on an always-on host. The launcher anchors configuration paths even when launchd starts it from another working directory.

If port 8501 is already occupied:

```bash
./scripts/aivi dashboard --port 8502
```

Then open [port 8502](http://127.0.0.1:8502). The dashboard continues to bind to `127.0.0.1`.

## PostgreSQL without Docker

You can use a native PostgreSQL server. With Homebrew installed:

```bash
brew install postgresql@17
brew services start postgresql@17
"$(brew --prefix postgresql@17)/bin/createuser" --pwprompt aivi
"$(brew --prefix postgresql@17)/bin/createdb" --owner=aivi aivi
```

The role command prompts for your chosen database password. Configure `DATABASE_URL=postgresql+psycopg://aivi:YOUR_URL_ENCODED_PASSWORD@localhost:5432/aivi` in your private `.env`, then run `./scripts/aivi init-db`. Consult the [Homebrew PostgreSQL formula](https://formulae.brew.sh/formula/postgresql@17) for current installation/service details. Native Homebrew database installation is optional and is not performed by this project's setup script.

## Validate locally

```bash
./scripts/setup_macos.sh --dev --skip-backfill
.venv/bin/python -m pytest -q
.venv/bin/python scripts/smoke_native.py
```

The smoke check imports the compiled dependencies, initializes a disposable SQLite database, generates and reopens an eight-sheet baseline workbook, and starts the real dashboard on an available localhost port. It launches the CLI from outside the project and uses temporary paths containing spaces. It shuts down its dashboard process and removes its test data afterwards; your production reports and checkpoints are untouched.

The GitHub Actions workflow includes a `macos-latest` job to run setup, tests, native startup checks and linting on future changes. Adding that workflow does not imply a remote CI run has already occurred.
