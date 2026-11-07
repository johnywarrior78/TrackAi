"""Synthetic source snapshots; no live findings or external services in unit tests."""

import io
import json
import shutil
import tarfile

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

from app.adapters.sources import CVE
from app.bootstrap import KEY, populate, status
from app.cli import cli
from app.database.models import (
    ApplicationSetting,
    Identifier,
    ReportRun,
    Source,
    Vulnerability,
    now,
)
from app.ingestion import sync_source
from app.queries import records

REVISION = "a" * 40


def cve(
    identifier="CVE-2025-12345",
    published="2025-05-12T08:00:00Z",
    credit="OpenAI TEST researcher",
):
    return {
        "cveMetadata": {
            "cveId": identifier,
            "state": "PUBLISHED",
            "datePublished": published,
        },
        "containers": {
            "cna": {
                "title": "Synthetic historical TEST finding",
                "credits": [{"value": credit}],
                "descriptions": [
                    {"lang": "en", "value": "Synthetic TEST fixture only"}
                ],
            }
        },
    }


@pytest.fixture
def history(db, tmp_path):
    db[2].cache_dir = tmp_path / "cache"
    db[2].history_batch_size = 1
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for raw in [
            cve("CVE-2025-10000", credit="unrelated TEST researcher"),
            cve(),
            cve("CVE-2023-12345", "2023-01-01T00:00:00Z", "Google Big Sleep TEST"),
        ]:
            body = json.dumps(raw).encode()
            year = raw["cveMetadata"]["cveId"].split("-")[1]
            member = tarfile.TarInfo(
                f"cvelistV5-{REVISION}/cves/{year}/12xxx/{raw['cveMetadata']['cveId']}.json"
            )
            member.size = len(body)
            tar.addfile(member, io.BytesIO(body))

    class FakeHTTP:
        downloads = 0

        def get(self, url):
            assert url.endswith("/commits/main")
            return {"sha": REVISION}

        def download(self, url, path, max_bytes):
            self.downloads += 1
            assert url.endswith(REVISION)
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(archive, path)

    http = FakeHTTP()
    return CVE(http, db[2], db[1]), http


def test_first_run_imports_all_years_and_preserves_may_2025(db, history):
    adapter, http = history
    result = sync_source(*db[:2], db[2], "cve", pages=adapter.fetch({}, True))
    assert result["status"] == "success" and result["created"] == 2
    with db[1]() as session:
        checkpoint = session.get(Source, "cve").checkpoint
        assert (
            checkpoint["history"]["complete"] and checkpoint["history"]["scanned"] == 3
        )
        may = session.scalar(
            select(Vulnerability)
            .join(Identifier)
            .where(Identifier.value == "CVE-2025-12345")
        )
        assert may.published == "2025-05-12T08:00:00Z"
        assert may.first_seen.date() == now().date()
        assert may.discovered is None
        assert session.scalar(select(func.count()).select_from(Vulnerability)) == 2
        filtered = list(
            records(
                session,
                db[2],
                date_field="Publication Date",
                date_start="2025-05-01",
                date_end="2025-06-01",
            )
        )
        assert len(filtered) == 1 and filtered[0]["CVE ID"] == "CVE-2025-12345"
    again = sync_source(*db[:2], db[2], "cve", pages=adapter.fetch(checkpoint, True))
    assert again["created"] == 0 and http.downloads == 1


def test_interrupted_historical_import_resumes_committed_batch(db, history):
    adapter, http = history

    def fail():
        for page in adapter.fetch({}, True):
            yield page
            if page.checkpoint["history"].get("scanned") == 2:
                raise OSError("Synthetic source interruption")

    assert sync_source(*db[:2], db[2], "cve", pages=fail())["status"] == "partial"
    with db[1]() as session:
        checkpoint = session.get(Source, "cve").checkpoint
        assert checkpoint["history"]["scanned"] == 2
    resumed = sync_source(*db[:2], db[2], "cve", pages=adapter.fetch(checkpoint, True))
    assert (
        resumed["status"] == "success"
        and resumed["created"] == 1
        and http.downloads == 1
    )
    with db[1]() as session:
        assert session.scalar(select(func.count()).select_from(Vulnerability)) == 2


def test_adp_attribution_is_discovered_without_false_ai_confirmation():
    raw = cve(credit="unrelated TEST credit")
    raw["containers"]["adp"] = [{"credits": [{"value": "Anthropic TEST researcher"}]}]
    record = CVE(None, None, None).normalize(raw)
    assert (
        record.create and record.facts["attribution"][0]["category"] == "credited_only"
    )
    assert not record.facts["attribution"][0].get("ai_use_confirmed")


def test_bootstrap_is_persistent_and_does_not_rescan(db, monkeypatch):
    calls = []

    def collect(engine, sessions, settings, backfill=False):
        calls.append(backfill)
        with sessions.begin() as session:
            session.add(
                Source(
                    name="cve",
                    checkpoint={
                        "history": {"complete": True, "scanned": 3, "matched": 2}
                    },
                )
            )
        return [{"source": "cve", "status": "success"}]

    monkeypatch.setattr("app.bootstrap.cycle", collect)
    assert populate(*db[:2], db[2])["status"] == "complete"
    assert populate(*db[:2], db[2])["status"] == "complete"
    assert calls == [True]
    with db[1]() as session:
        assert session.scalar(select(ReportRun)).baseline
        assert session.get(ApplicationSetting, KEY).value["history_matched"] == 2


def test_failure_is_not_marked_initialized_and_retries(db, monkeypatch):
    monkeypatch.setattr(
        "app.bootstrap.cycle",
        lambda *args, **kwargs: [{"source": "cve", "status": "failure"}],
    )
    assert populate(*db[:2], db[2])["status"] == "incomplete"
    assert status(db[1])["status"] == "incomplete"
    assert populate(*db[:2], db[2])["status"] == "incomplete"
    with db[1]() as session:
        assert session.scalar(select(func.count()).select_from(ReportRun)) == 0


def test_offline_opt_out_does_not_mark_complete(db):
    db[2].auto_backfill = False
    assert populate(*db[:2], db[2])["status"] == "disabled"
    assert status(db[1])["status"] == "not_started"


def test_dashboard_initializes_by_default(monkeypatch):
    called = []
    monkeypatch.setenv("AUTO_BACKFILL", "true")
    monkeypatch.setattr("app.cli.initialize", lambda force: called.append("initialize"))
    monkeypatch.setattr(
        "app.cli.subprocess.run", lambda *args, **kwargs: called.append("dashboard")
    )
    assert CliRunner().invoke(cli, ["dashboard"]).exit_code == 0
    assert called == ["initialize", "dashboard"]


def test_publication_date_is_filtered_before_pagination(db):
    with db[1].begin() as session:
        session.add_all(
            [
                Vulnerability(title=f"TEST recent {i}", published="2026-11-01")
                for i in range(501)
            ]
        )
        session.add(Vulnerability(title="TEST May 2025", published="2025-05-12"))
    with db[1]() as session:
        rows = list(
            records(
                session,
                db[2],
                limit=500,
                date_field="Publication Date",
                date_start="2025-05-01",
                date_end="2025-06-01",
            )
        )
        assert len(rows) == 1 and rows[0]["Vulnerability Title"] == "TEST May 2025"


def test_native_sqlite_lock_releases_after_abrupt_process_exit(db):
    import select as select_io
    import subprocess
    import sys
    from app.database.session import job_lock

    if db[0].dialect.name != "sqlite":
        pytest.skip(
            "PostgreSQL advisory crash recovery uses its own connection lifecycle"
        )
    code = """import sys,time
from app.database.session import connect,job_lock
engine,sessions=connect(sys.argv[1])
with job_lock(engine,sessions,'bootstrap'):
 print('locked',flush=True)
 time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", code, db[2].database_url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select_io.select([process.stdout], [], [], 10)
        assert ready and process.stdout.readline().strip() == "locked"
        with pytest.raises(RuntimeError):
            with job_lock(*db[:2], "bootstrap"):
                pass
        process.kill()
        process.wait(timeout=5)
        with job_lock(*db[:2], "bootstrap"):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def test_empty_local_corpus_is_not_marked_complete(db, tmp_path):
    folder = tmp_path / "empty-cve"
    (folder / "cves").mkdir(parents=True)
    db[2].cve_repo_path = str(folder)
    adapter = CVE(None, db[2], db[1])
    result = sync_source(*db[:2], db[2], "cve", pages=adapter.fetch({}, True))
    assert result["status"] == "failure"
    with db[1]() as session:
        assert (
            not session.get(Source, "cve").checkpoint.get("history", {}).get("complete")
        )
