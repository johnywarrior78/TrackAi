"""Restartable first-run population; completion is not inferred from row counts."""

from sqlalchemy import select
from app.database.models import ApplicationSetting, ReportRun, Source, now
from app.database.session import job_lock
from app.ingestion import cycle
from app.reporting.excel import generate

KEY = "initial_historical_backfill"


def status(sessions):
    with sessions() as session:
        setting = session.get(ApplicationSetting, KEY)
        return dict(setting.value) if setting else {"status": "not_started"}


def populate(engine, sessions, settings, force=False):
    if not settings.auto_backfill and not force:
        return {"status": "disabled"}
    with job_lock(engine, sessions, "bootstrap"):
        previous = status(sessions)
        if previous.get("status") == "complete" and not force:
            return previous
        with sessions.begin() as session:
            setting = session.get(ApplicationSetting, KEY)
            if not setting:
                setting = ApplicationSetting(key=KEY)
                session.add(setting)
            setting.value = {
                "status": "running",
                "started_at": previous.get("started_at") or now().isoformat(),
            }
        try:
            results = cycle(engine, sessions, settings, backfill=True)
            failures = [r["source"] for r in results if r["status"] != "success"]
            with sessions() as session:
                cve = session.get(Source, "cve")
                history = (cve.checkpoint or {}).get("history", {}) if cve else {}
            if not history.get("complete"):
                failures.append("cve-history")
            if failures:
                outcome = {
                    "status": "incomplete",
                    "failed_sources": sorted(set(failures)),
                    "results": results,
                }
            else:
                with sessions() as session:
                    pending = [
                        source.name
                        for source in session.scalars(select(Source))
                        if (source.checkpoint or {}).get("cve")
                        or (source.checkpoint or {}).get("identifier")
                    ]
                # A historical inventory is a baseline, never "all newly discovered today".
                with sessions() as session:
                    has_report = session.scalar(
                        select(ReportRun.id)
                        .where(
                            ReportRun.status == "success", ReportRun.custom.is_(False)
                        )
                        .limit(1)
                    )
                if not has_report:
                    generate(engine, sessions, settings)
                outcome = {
                    "status": "complete",
                    "completed_at": now().isoformat(),
                    "results": results,
                    "enrichment_pending": pending,
                    "history_scanned": history.get("scanned"),
                    "history_matched": history.get("matched"),
                }
        except Exception as exc:
            with sessions.begin() as session:
                session.get(ApplicationSetting, KEY).value = {
                    "status": "incomplete",
                    "error": type(exc).__name__,
                }
            raise
        with sessions.begin() as session:
            session.get(ApplicationSetting, KEY).value = outcome
        return outcome
