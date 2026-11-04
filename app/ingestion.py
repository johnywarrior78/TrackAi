import hashlib
import json
import logging
from time import monotonic
from sqlalchemy import select, update
from app.database.models import (
    Source,
    SourceRecord,
    Snapshot,
    Vulnerability,
    Identifier,
    Fact,
    Change,
    ScoreHistory,
    Run,
    Metric,
    now,
)
from app.database.session import job_lock
from app.domain import identifier
from app.adapters import ADAPTERS
from app.adapters.http import PublicHTTP

log = logging.getLogger("ingestion")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def merge(s, ids):
    """Explicit shared identifiers only. Existing clusters may bridge CVE and GHSA."""
    winner = min(ids)
    for loser in sorted(ids - {winner}):
        for model in (Identifier, SourceRecord, Change, ScoreHistory):
            s.execute(
                update(model)
                .where(model.vulnerability_id == loser)
                .values(vulnerability_id=winner)
            )
        for fact in list(s.scalars(select(Fact).where(Fact.vulnerability_id == loser))):
            existing = s.scalar(
                select(Fact).where(
                    Fact.vulnerability_id == winner,
                    Fact.source == fact.source,
                    Fact.kind == fact.kind,
                    Fact.key == fact.key,
                )
            )
            if existing:
                s.add(
                    Change(
                        vulnerability_id=winner,
                        source="correlation",
                        field="merge_fact",
                        previous=fact.data,
                        current=existing.data,
                    )
                )
                s.delete(fact)
            else:
                fact.vulnerability_id = winner
        old, new = s.get(Vulnerability, loser), s.get(Vulnerability, winner)
        new.first_seen = min(new.first_seen, old.first_seen)
        s.add(
            Change(
                vulnerability_id=winner,
                source="correlation",
                field="merge",
                previous={"id": loser},
                current={"id": winner},
            )
        )
        s.flush()
        s.delete(old)
    s.flush()
    return winner


def ingest(s, source, record):
    record.validate()
    old = s.scalar(
        select(SourceRecord).where(
            SourceRecord.source == source, SourceRecord.key == record.key
        )
    )
    d = digest(record.__dict__)
    timestamp = now()
    if old and old.digest == d and (old.vulnerability_id is not None or record.sealed):
        old.observed_at = timestamp
        if old.vulnerability_id:
            s.get(Vulnerability, old.vulnerability_id).last_seen = timestamp
        return "unchanged"
    candidates = (
        set(
            s.scalars(
                select(Identifier.vulnerability_id).where(
                    Identifier.value.in_(record.ids)
                )
            )
        )
        if record.ids
        else set()
    )
    if old and old.vulnerability_id:
        candidates.add(old.vulnerability_id)
    vid = merge(s, candidates) if candidates else None
    created = False
    if not vid and not record.sealed and record.create:
        v = Vulnerability(title=record.title or "Unknown")
        s.add(v)
        s.flush()
        vid = v.id
        created = True
    # Unmatched enrichment never creates an unrelated vulnerability.
    if not old:
        old = SourceRecord(
            source=source,
            key=record.key,
            digest=d,
            payload=record.raw,
            vulnerability_id=vid,
        )
        s.add(old)
        s.flush()
    else:
        old.digest, old.payload, old.vulnerability_id, old.observed_at = (
            d,
            record.raw,
            vid,
            timestamp,
        )
    s.add(
        Snapshot(record_id=old.id, digest=d, payload=record.raw, observed_at=timestamp)
    )
    if not vid:
        return "stored"
    v = s.get(Vulnerability, vid)
    v.last_seen = timestamp
    if source in ("cve", "ghsa", "kev", "epss"):
        v.enriched_at = timestamp
    for value in record.ids:
        if not s.get(Identifier, value):
            s.add(
                Identifier(value=value, kind=identifier(value)[1], vulnerability_id=vid)
            )
    # Authority-aware canonical projection. Every conflicting raw value remains in snapshots.
    for field in ("title", "description", "published", "discovered", "state"):
        value = getattr(record, field)
        previous = getattr(v, field)
        if (
            value is not None
            and value != previous
            and (
                source == "cve"
                or field == "discovered"
                or previous in (None, "Unknown", "published")
                or (field == "title" and str(previous).startswith("ANT-"))
                or created
            )
        ):
            if not created:
                s.add(
                    Change(
                        vulnerability_id=vid,
                        source=source,
                        field=field,
                        previous={"value": previous},
                        current={"value": value},
                    )
                )
            setattr(v, field, value)
    for kind, facts in record.facts.items():
        # EPSS historical imports must never roll current state backwards.
        if kind == "epss":
            for data in facts:
                h = s.scalar(
                    select(ScoreHistory).where(
                        ScoreHistory.cve == data["cve"],
                        ScoreHistory.date == data["date"],
                    )
                )
                if not h:
                    s.add(
                        ScoreHistory(
                            vulnerability_id=vid,
                            cve=data["cve"],
                            date=data["date"],
                            probability=data["probability"],
                            percentile=data["percentile"],
                        )
                    )
        current = list(
            s.scalars(
                select(Fact).where(
                    Fact.vulnerability_id == vid,
                    Fact.source == source,
                    Fact.kind == kind,
                )
            )
        )
        bykey = {f.key: f for f in current}
        seen = set()
        for i, data in enumerate(facts):
            key = str(data.get("key", data.get("cve", i)))
            seen.add(key)
            f = bykey.get(key)
            if kind == "epss" and f and f.data["date"] > data["date"]:
                continue
            if not f or f.data != data:
                if not created:
                    s.add(
                        Change(
                            vulnerability_id=vid,
                            source=source,
                            field=f"{kind}:{key}",
                            previous=f.data if f else None,
                            current=data,
                        )
                    )
                if f:
                    f.data = data
                else:
                    s.add(
                        Fact(
                            vulnerability_id=vid,
                            source=source,
                            kind=kind,
                            key=key,
                            data=data,
                        )
                    )
        for key, f in bykey.items():
            if key not in seen:
                s.add(
                    Change(
                        vulnerability_id=vid,
                        source=source,
                        field=f"{kind}:{key}",
                        previous=f.data,
                        current=None,
                    )
                )
                s.delete(f)
    return "created" if created else "updated"


def sync_source(engine, sessions, settings, name, backfill=False, pages=None):
    http = PublicHTTP(settings)
    start = monotonic()
    with job_lock(engine, sessions, "collection"):
        with sessions.begin() as s:
            source = s.get(Source, name)
            if not source:
                source = Source(name=name)
                s.add(source)
                s.flush()
            source.last_attempt = now()
            source.status = "running"
            checkpoint = source.checkpoint
            run = Run(source=name)
            s.add(run)
            s.flush()
            run_id = run.id
        stats = {"processed": 0, "created": 0, "updated": 0, "failed": 0}
        try:
            adapter = ADAPTERS[name](http, settings, sessions)
            iterator = (
                pages
                if pages is not None
                else adapter.synchronize(checkpoint, backfill)
            )
            for page in iterator:
                counts = {"processed": 0, "created": 0, "updated": 0}
                # Page errors roll back the whole page and leave its checkpoint intact.
                with sessions.begin() as s:
                    for record in page.records:
                        result = ingest(s, name, record)
                        counts["processed"] += 1
                        if result in counts:
                            counts[result] += 1
                    s.get(Source, name).checkpoint = page.checkpoint
                    run = s.get(Run, run_id)
                    for key, n in counts.items():
                        setattr(run, key, getattr(run, key) + n)
                for key, n in counts.items():
                    stats[key] += n
            status = "success"
            error = None
        except Exception as exc:
            status = "partial" if stats["processed"] else "failure"
            # Never log response headers, credentials, or a configurable DB URL.
            error = f"{type(exc).__name__}: source failed; check connectivity/schema and retry"
            stats["failed"] += 1
        finally:
            with sessions.begin() as s:
                source = s.get(Source, name)
                source.status = status
                source.error = error
                if status == "success":
                    source.last_success = now()
                run = s.get(Run, run_id)
                run.status = status
                run.finished = now()
                run.error = error
                run.failed = stats["failed"]
                run.errors = http.errors
                run.rate_limits = http.rate_limits
            http.close()
        log.info(
            "source_sync",
            extra={
                "fields": {
                    "source": name,
                    "execution_id": run_id,
                    "duration": round(monotonic() - start, 3),
                    "status": status,
                    **stats,
                }
            },
        )
        return {"source": name, "status": status, **stats}


def cycle(engine, sessions, settings, backfill=False):
    results = []
    for name in ("anthropic", "cve", "ghsa", "kev", "epss"):
        results.append(sync_source(engine, sessions, settings, name, backfill))
    from app.queries import metrics

    with sessions.begin() as s:
        day = now().date().isoformat()
        metric = s.get(Metric, day)
        # An actual observation only. No invented dates for historical backfills.
        if not metric:
            s.add(Metric(day=day, data=metrics(s)))
        else:
            metric.data = metrics(s)
            metric.observed_at = now()
    return results
