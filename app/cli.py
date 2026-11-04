import json
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional
import typer
from sqlalchemy import select, text
from alembic.config import Config
from alembic import command
from app.config import Settings
from app.database.session import connect, job_lock
from app.database.models import Fact
from app.logging import configure
from app.ingestion import cycle, sync_source
from app.adapters import ADAPTERS
from app.adapters.http import PublicHTTP
from app.queries import health as source_health
from app.reporting.excel import generate

cli = typer.Typer(
    help="Evidence-first AI vulnerability intelligence. Dates and schedules are UTC.",
    no_args_is_help=True,
)


def runtime():
    settings = Settings()
    configure(settings.log_dir)
    engine, sessions = connect(settings.database_url)
    return settings, engine, sessions


@cli.command("init-db")
def init_db():
    """Apply Alembic migrations to the configured database."""
    command.upgrade(Config("alembic.ini"), "head")
    typer.echo("Database initialized")


@cli.command()
def sync(
    source: Optional[str] = typer.Option(
        None, help="One source; otherwise all enabled sources"
    ),
):
    """Incremental synchronization, isolating failures by source."""
    settings, engine, sessions = runtime()
    if source and source not in ADAPTERS:
        raise typer.BadParameter("Unknown source")
    results = (
        [sync_source(engine, sessions, settings, source)]
        if source
        else cycle(engine, sessions, settings)
    )
    typer.echo(json.dumps(results))
    if any(r["status"] != "success" for r in results):
        raise typer.Exit(1)


@cli.command()
def backfill(source: Optional[str] = typer.Option(None)):
    """Resumable historical collection; CVE_REPO_PATH enables full credit search."""
    settings, engine, sessions = runtime()
    if source and source not in ADAPTERS:
        raise typer.BadParameter("Unknown source")
    results = (
        [sync_source(engine, sessions, settings, source, True)]
        if source
        else cycle(engine, sessions, settings, True)
    )
    typer.echo(json.dumps(results))
    if any(r["status"] != "success" for r in results):
        raise typer.Exit(1)


@cli.command("refresh-epss")
def refresh_epss(start: Optional[str] = None, end: Optional[str] = None):
    """Refresh current EPSS, or selectively backfill ISO dates (max 365 days)."""
    settings, engine, sessions = runtime()
    if bool(start) != bool(end):
        raise typer.BadParameter("Both start and end are required")
    if start:
        from app.adapters.sources import EPSS

        http = PublicHTTP(settings)
        try:
            pages = EPSS(http, settings, sessions).history(
                date.fromisoformat(start), date.fromisoformat(end)
            )
            result = sync_source(engine, sessions, settings, "epss", pages=pages)
        finally:
            http.close()
    else:
        result = sync_source(engine, sessions, settings, "epss")
    typer.echo(json.dumps(result))
    if result["status"] != "success":
        raise typer.Exit(1)


@cli.command("refresh-kev")
def refresh_kev():
    """Refresh tracked identifiers against the complete current KEV catalog."""
    sync("kev")


@cli.command()
def report(start: Optional[str] = None, end: Optional[str] = None):
    """Daily Excel report, or custom first-seen UTC range [start,end)."""
    settings, engine, sessions = runtime()

    def parse(value):
        if not value:
            return None
        dt = datetime.fromisoformat(value)
        return (
            dt.replace(tzinfo=timezone.utc)
            if not dt.tzinfo
            else dt.astimezone(timezone.utc)
        )

    a, b = parse(start), parse(end)
    if a and b and a >= b:
        raise typer.BadParameter("start must precede end")
    typer.echo(str(generate(engine, sessions, settings, a, b)))


@cli.command()
def dashboard(
    port: int = typer.Option(8501, min=1, max=65535, help="Local dashboard TCP port."),
):
    """Start the dashboard on localhost (default port 8501)."""
    subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(Path(__file__).parent / "dashboard" / "main.py"),
            "--server.headless",
            "true",
            "--browser.gatherUsageStats",
            "false",
            "--server.address",
            "127.0.0.1",
            "--server.port",
            str(port),
        ],
        check=True,
    )


@cli.command("check-sources")
def check_sources(source: Optional[str] = None):
    """Check public connectivity without advancing ingestion checkpoints."""
    settings, _, sessions = runtime()
    http = PublicHTTP(settings)
    failed = False
    if source and source not in ADAPTERS:
        raise typer.BadParameter("Unknown source")
    try:
        for name in [source] if source else ADAPTERS:
            try:
                ADAPTERS[name](http, settings, sessions).connectivity()
                typer.echo(f"{name}: reachable")
            except Exception as exc:
                failed = True
                typer.echo(f"{name}: unavailable ({type(exc).__name__})")
    finally:
        http.close()
    if failed:
        raise typer.Exit(1)


@cli.command()
def health():
    """Database connectivity and persisted source freshness; nonzero if unhealthy."""
    _, engine, sessions = runtime()
    with engine.connect() as c:
        c.execute(text("SELECT 1"))
    with sessions() as s:
        rows = source_health(s)
    typer.echo(json.dumps(rows))
    if not rows or any(
        r["Status"] != "success" or r["Completeness Warning"] for r in rows
    ):
        raise typer.Exit(1)


@cli.command("verify-attribution")
def verify_attribution():
    """Audit confirmed claims for missing evidence; does not promote affiliations."""
    _, _, sessions = runtime()
    issues = []
    counts = {}
    with sessions() as s:
        for f in s.scalars(select(Fact).where(Fact.kind == "attribution")):
            a = f.data
            category = a.get("category", "unknown")
            counts[category] = counts.get(category, 0) + 1
            if category in ("autonomous", "human_assisted") and not (
                a.get("claim") and a.get("evidence_url")
            ):
                issues.append(f.id)
    typer.echo(json.dumps({"claims": counts, "invalid_evidence_fact_ids": issues}))
    if issues:
        raise typer.Exit(1)


@cli.command()
def scheduler():
    """One UTC scheduled collection/report cycle daily; one scheduler per database."""
    from apscheduler.schedulers.blocking import BlockingScheduler

    settings, engine, sessions = runtime()

    def job():
        # Singleton scheduler plus ingestion/report locks protect manual invocations.
        results = cycle(engine, sessions, settings)
        path = generate(engine, sessions, settings)
        import logging

        logging.getLogger("scheduler").info(
            "cycle_complete",
            extra={"fields": {"results": results, "report": str(path)}},
        )

    with job_lock(engine, sessions, "scheduler"):
        scheduler = BlockingScheduler(timezone="UTC")
        scheduler.add_job(
            job,
            "cron",
            hour=settings.schedule_hour,
            minute=settings.schedule_minute,
            id="daily",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=3600,
        )
        typer.echo(
            "Scheduler running (UTC); run aivi sync/report for an immediate cycle"
        )
        scheduler.start()


def main():
    cli()


if __name__ == "__main__":
    main()
