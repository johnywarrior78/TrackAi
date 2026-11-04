"""Entirely synthetic TEST fixtures; never imported as live intelligence."""

from datetime import timedelta
import pytest
from sqlalchemy import select, func
from openpyxl import load_workbook
from app.database.models import (
    Source,
    SourceRecord,
    Vulnerability,
    Identifier,
    Snapshot,
    Fact,
    Change,
    ScoreHistory,
    ReportRun,
    now,
)
from app.domain import Record, identifier, credits_claim, cvss_assessments, priority
from app.ingestion import ingest, sync_source, cycle
from app.adapters.sources import Anthropic, CVE, KEV, EPSS, Page
from app.database.session import job_lock
from app.reporting.excel import generate, Sheets, safe
from app.adapters.http import validate_url, PublicHTTP

CVE_ID = "CVE-2099-12345"
GHSA_ID = "GHSA-2345-6789-cfgh"


def record(version=1, ids=None, **kw):
    return Record(
        "test-finding",
        {"synthetic": True, "version": version},
        ids or [CVE_ID],
        title="Synthetic TEST finding",
        facts={
            "severity": [{"score": 9.1, "severity": "critical", "assessor": "TEST"}]
        },
        **kw,
    )


def put(db, r, source="test"):
    _, sessions, _ = db
    with sessions.begin() as s:
        if not s.get(Source, source):
            s.add(Source(name=source))
            s.flush()
        return ingest(s, source, r)


@pytest.mark.parametrize(
    "raw,expected", [(" cve-2099-12345 ", CVE_ID), ("ghsa-2345-6789-cfgh", GHSA_ID)]
)
def test_identifier(raw, expected):
    assert identifier(raw)[0] == expected


@pytest.mark.parametrize(
    "raw", ["CVE-1-2", "http://bad", "GHSA-abcd-abcd-abcd", "=1+1"]
)
def test_invalid_identifiers(raw):
    with pytest.raises(ValueError):
        identifier(raw)


def test_idempotency_history(db):
    assert put(db, record()) == "created"
    assert put(db, record()) == "unchanged"
    r = record(2)
    r.facts["severity"][0]["score"] = 5.0
    assert put(db, r) == "updated"
    with db[1]() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 1
        assert s.scalar(select(func.count()).select_from(Snapshot)) == 2
        assert s.scalar(select(Change)).previous["score"] == 9.1


def test_bridge_correlation(db):
    put(db, record(ids=[CVE_ID]))
    r = record(ids=[GHSA_ID])
    r.key = "other"
    r.title = "Different title"
    put(db, r, "second")
    bridge = record(3, ids=[CVE_ID, GHSA_ID])
    put(db, bridge, "third")
    with db[1]() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 1
        assert len(set(s.scalars(select(Identifier.vulnerability_id)))) == 1


def test_title_does_not_merge(db):
    put(db, record())
    r = record(ids=["CVE-2099-12346"])
    r.key = "different"
    put(db, r)
    with db[1]() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 2


def test_sealed_ledger(db):
    a = Anthropic(None, None, None)
    r = {
        "hash": "a" * 128,
        "revealed": False,
        "cve_ids": [CVE_ID],
        "project": "DO NOT EXPOSE",
    }
    put(db, a.normalize(r), "anthropic")
    with db[1]() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 0
        assert s.scalar(select(func.count()).select_from(Identifier)) == 0


def test_reveal_and_multi_assessment(db):
    a = Anthropic(None, None, None)
    raw = {"hash": "b" * 128, "revealed": False}
    put(db, a.normalize(raw), "anthropic")
    raw.update(
        revealed=True,
        ant_id="TEST-ONLY",
        project="TEST",
        claude_severity="critical",
        vendor_severity="medium",
        cve_ids=[CVE_ID],
    )
    put(db, a.normalize(raw), "anthropic")
    with db[1]() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 1
        assert (
            s.scalar(
                select(func.count()).select_from(Fact).where(Fact.kind == "severity")
            )
            == 2
        )
        attr = s.scalar(select(Fact).where(Fact.kind == "attribution")).data
        assert (
            attr["category"] == "unknown"
            and attr["ai_use_confirmed"] is True
            and attr["model"] is None
        )


def test_affiliation_never_implies_ai():
    a = credits_claim("Researcher at OpenAI", "https://example.org")
    assert a[0]["category"] == "credited_only"
    assert credits_claim("No attribution", "https://example.org") == []


@pytest.mark.parametrize("category", ["autonomous", "human_assisted"])
def test_confirmed_needs_evidence(category):
    r = record()
    r.facts = {"attribution": [{"category": category}]}
    with pytest.raises(ValueError):
        r.validate()
    r.facts["attribution"][0].update(
        claim="TEST claim", evidence_url="https://example.org"
    )
    r.validate()


def test_ambiguous_attribution():
    for category in ["unknown", "unverified", "credited_only"]:
        r = record()
        r.facts = {"attribution": [{"category": category}]}
        r.validate()


def test_cvss():
    assert (
        cvss_assessments(
            [
                {
                    "cvssV3_1": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "version": "3.1",
                    }
                }
            ]
        )[0]["score"]
        == 9.8
    )
    with pytest.raises(ValueError):
        cvss_assessments([{"cvssV3_1": {"baseScore": 11}}])


def test_epss_history_does_not_roll_back(db):
    put(db, record())
    a = EPSS(None, None, None)
    for date, score in [("2026-02-02", ".5"), ("2026-01-01", ".1")]:
        put(
            db,
            a.normalize(
                {"cve": CVE_ID, "date": date, "epss": score, "percentile": ".9"}
            ),
            "epss",
        )
    with db[1]() as s:
        assert s.scalar(select(func.count()).select_from(ScoreHistory)) == 2
        assert (
            s.scalar(select(Fact).where(Fact.kind == "epss")).data["probability"] == 0.5
        )
    with pytest.raises(ValueError):
        a.normalize(
            {"cve": CVE_ID, "date": "2026-01-01", "epss": "1.5", "percentile": ".2"}
        )


def test_kev_history(db):
    put(db, record())
    put(
        db,
        KEV(None, None, None).normalize({"cveID": CVE_ID, "dateAdded": "2026-01-01"}),
        "kev",
    )
    put(
        db,
        Record(
            CVE_ID,
            {"present": False},
            [CVE_ID],
            facts={"kev": [{"present": False}]},
            create=False,
        ),
        "kev",
    )
    with db[1]() as s:
        assert s.scalar(select(Fact).where(Fact.kind == "kev")).data["present"] is False
        assert len(list(s.scalars(select(Change).where(Change.field == "kev:0")))) == 2


def test_source_recovery_and_checkpoint(db):
    engine, sessions, settings = db

    def broken():
        yield Page([record()], {"cursor": 1})
        raise RuntimeError("outage")

    result = sync_source(engine, sessions, settings, "anthropic", pages=broken())
    assert result["status"] == "partial"
    with sessions() as s:
        assert s.get(Source, "anthropic").checkpoint == {"cursor": 1}
    assert (
        sync_source(
            engine,
            sessions,
            settings,
            "anthropic",
            pages=[Page([record()], {"cursor": 2})],
        )["status"]
        == "success"
    )
    with sessions() as s:
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 1


def test_page_failure_rollback(db):
    bad = record()
    bad.ids = ["invalid"]
    r = sync_source(
        *db[:2], db[2], "anthropic", pages=[Page([record(), bad], {"cursor": 99})]
    )
    assert r["status"] == "failure"
    with db[1]() as s:
        assert s.get(Source, "anthropic").checkpoint == {}
        assert s.scalar(select(func.count()).select_from(Vulnerability)) == 0


def test_baseline_report_checkpoint(db):
    put(db, record())
    before = None
    with db[1]() as s:
        before = s.get(Source, "test").checkpoint
    path = generate(*db[:2], db[2])
    wb = load_workbook(path)
    assert len(wb.sheetnames) == 8
    assert wb["New Vulnerabilities"].max_row == 1
    assert "BASELINE" in str(list(wb["Executive Summary"].values))
    assert wb["Critical and High"].max_row == 2
    assert wb["Critical and High"]["A1"].value == "First Seen"
    second = generate(*db[:2], db[2])
    assert second != path
    assert load_workbook(second)["New Vulnerabilities"].max_row == 1
    with db[1]() as s:
        assert s.get(Source, "test").checkpoint == before
        assert (
            s.scalar(
                select(func.count())
                .select_from(ReportRun)
                .where(ReportRun.status == "success")
            )
            == 2
        )


def test_new_and_updated_report(db):
    put(db, record())
    generate(*db[:2], db[2])
    r = record(2)
    r.facts["severity"][0]["score"] = 7.5
    put(db, r)
    new = record(ids=["CVE-2099-99999"])
    new.key = "new"
    put(db, new)
    path = generate(*db[:2], db[2])
    wb = load_workbook(path)
    assert wb["New Vulnerabilities"].max_row == 2
    assert wb["Updated Vulnerabilities"].max_row == 2


def test_empty_report(db):
    wb = load_workbook(generate(*db[:2], db[2]))
    assert wb["New Vulnerabilities"].max_row == 1


def test_custom_does_not_advance_daily(db):
    generate(*db[:2], db[2])
    custom = generate(*db[:2], db[2], start=now() - timedelta(days=1))
    with db[1]() as s:
        assert s.scalar(
            select(ReportRun).where(ReportRun.custom.is_(True))
        ).path == str(custom.resolve())
        assert (
            s.scalar(
                select(func.count())
                .select_from(ReportRun)
                .where(ReportRun.custom.is_(False))
            )
            == 1
        )


@pytest.mark.parametrize("text", ["=1+1", " +cmd", "-1", "@SUM(1)", "\t=cmd"])
def test_formula_injection(text):
    assert safe(text).startswith("'")


def test_excel_formula_neutralized(db):
    r = record()
    r.title = '=HYPERLINK("https://example.org")'
    put(db, r)
    wb = load_workbook(generate(*db[:2], db[2]))
    cell = wb["Critical and High"]["D2"]
    assert cell.data_type == "s" and cell.value.startswith("'")


def test_excel_splitting():
    from openpyxl import Workbook

    book = Workbook(write_only=True)
    s = Sheets(book, "TEST", ["ID"], max_rows=3)
    for i in range(5):
        s.append({"ID": i})
    s.finish()
    assert len(book.worksheets) == 3
    import tempfile

    with tempfile.TemporaryFile() as f:
        book.save(f)


def test_lock(db):
    with job_lock(*db[:2], "test-lock"):
        with pytest.raises(RuntimeError):
            with job_lock(*db[:2], "test-lock"):
                pass
    with job_lock(*db[:2], "test-lock"):
        pass


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com",
        "https://127.0.0.1/x",
        "https://api.github.com@localhost/x",
        "https://api.github.com:444/x",
        "file:///etc/passwd",
    ],
)
def test_ssrf(url):
    with pytest.raises(ValueError):
        validate_url(url, resolve=False)


def test_priority_unknown(db):
    p, reason = priority(
        {"CVSS Score": None, "EPSS Score": None, "CISA KEV": None},
        db[2].priority_config,
    )
    assert p == "P4" and "validation" in reason
    assert priority({"CISA KEV": True}, db[2].priority_config)[0] == "P1"


def test_http_retry(httpx_mock, db, monkeypatch):
    monkeypatch.setattr("app.adapters.http.validate_url", lambda url: url)
    monkeypatch.setattr("app.adapters.http.time.sleep", lambda _: None)
    httpx_mock.add_response(status_code=429, headers={"retry-after": "0"})
    httpx_mock.add_response(json={"ok": True})
    h = PublicHTTP(db[2])
    assert h.get("https://api.first.org/data/v1/epss") == {"ok": True}
    assert h.rate_limits == 1
    h.close()


def test_cve_rejected():
    r = CVE(None, None, None).normalize(
        {"cveMetadata": {"cveId": CVE_ID, "state": "REJECTED"}, "containers": {}}
    )
    assert r.state == "rejected"


def test_long_excel_text_lossless(tmp_path):
    from openpyxl import Workbook

    book = Workbook(write_only=True)
    sheet = Sheets(book, "TEST", ["Text"])
    text = "x" * 70000
    sheet.append({"Text": text})
    sheet.finish()
    book._aivi_overflow.finish()
    path = tmp_path / "long.xlsx"
    book.save(path)
    wb = load_workbook(path)
    assert "".join(row[-1] for row in list(wb["Long Text"].values)[1:]) == text
    assert "Long Text" in wb["TEST"]["A2"].value


def test_corrected_identifier_is_not_alias():
    r = Anthropic(None, None, None).normalize(
        {
            "hash": "a" * 128,
            "revealed": True,
            "cve_ids": [CVE_ID],
            "corrected_cve_ids": [CVE_ID],
            "ghsa_ids": [GHSA_ID],
        }
    )
    assert CVE_ID not in r.ids and GHSA_ID in r.ids


def test_enrichment_observed_before_discovery(db):
    r = record()
    r.create = False
    put(db, r, "cve")
    put(db, record(), "anthropic")
    assert put(db, r, "cve") == "updated"
    with db[1]() as s:
        assert (
            s.scalar(
                select(SourceRecord).where(SourceRecord.source == "cve")
            ).vulnerability_id
            is not None
        )


def test_malformed_url_is_safe_excel(db):
    r = record()
    r.title = "http://[malformed"
    put(db, r)
    assert generate(*db[:2], db[2]).is_file()


def test_failed_report_preserves_checkpoint(db, monkeypatch):
    generate(*db[:2], db[2])
    with db[1]() as s:
        first = s.scalar(
            select(ReportRun).where(ReportRun.status == "success")
        ).checkpoint

    def fail(*a, **kw):
        raise OSError("test disk full")

    monkeypatch.setattr("app.reporting.excel.os.replace", fail)
    with pytest.raises(OSError):
        generate(*db[:2], db[2])
    with db[1]() as s:
        assert (
            s.scalar(select(ReportRun).where(ReportRun.status == "success")).checkpoint
            == first
        )
        assert (
            s.scalar(select(ReportRun).where(ReportRun.status == "failure")) is not None
        )


def test_enrichment_failure_does_not_block_sources(db, monkeypatch):
    called = []

    def source(engine, sessions, settings, name, backfill=False):
        called.append(name)
        return {
            "source": name,
            "status": "failure" if name == "anthropic" else "success",
        }

    monkeypatch.setattr("app.ingestion.sync_source", source)
    results = cycle(*db[:2], db[2])
    assert called == ["anthropic", "cve", "ghsa", "kev", "epss"]
    assert len(results) == 5 and results[-1]["status"] == "success"


def test_bulk_epss_cached_and_filtered(db, tmp_path):
    import gzip

    db[2].cache_dir = tmp_path / "cache"

    class FakeHTTP:
        calls = 0

        def get(self, url, binary=False):
            self.calls += 1
            assert binary and "empiricalsec/epss_scores" in url
            return gzip.compress(
                f"#model_version:TEST\ncve,epss,percentile\n{CVE_ID},0.5,0.9\nCVE-2099-55555,0.1,0.2\n".encode()
            )

    http = FakeHTTP()
    adapter = EPSS(http, db[2], db[1])
    first = list(adapter.bulk([CVE_ID], "2026-01-01"))
    second = list(adapter.bulk([CVE_ID], "2026-01-01"))
    assert http.calls == 1 and len(first[0].records) == 1
    assert second[0].records[0].facts["epss"][0]["probability"] == 0.5


def test_control_characters_in_untrusted_report(db):
    r = record()
    r.title = "TEST\x00\x0btitle"
    put(db, r)
    path = generate(*db[:2], db[2])
    assert (
        load_workbook(path)["Critical and High"]["D2"].value
        == "TEST\\u0000\\u000btitle"
    )
