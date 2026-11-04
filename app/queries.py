"""Shared read model for dashboard and reports; one row per vulnerability."""

from collections import defaultdict
from datetime import timedelta
from sqlalchemy import select, func
from app.database.models import Vulnerability, Identifier, Fact, Source, Run, now
from app.domain import priority

COLUMNS = [
    "First Seen",
    "CVE ID",
    "GHSA ID",
    "Vulnerability Title",
    "AI Organization",
    "AI Model",
    "Discovery Attribution",
    "Attribution Evidence URL",
    "Vendor",
    "Affected Product",
    "Affected Versions",
    "Fixed Version",
    "CVSS Score",
    "CVSS Severity",
    "EPSS Score",
    "EPSS Percentile",
    "CISA KEV",
    "CWE",
    "Vulnerability Category",
    "Publication Date",
    "Discovery Date",
    "Patch Available",
    "Remediation",
    "Operational Priority",
    "Source URL",
    "Priority Explanation",
    "ID",
    "State",
    "AI Use Confirmed",
]


def join(values):
    return "; ".join(dict.fromkeys(str(x) for x in values if x is not None and x != ""))


def records(s, settings, start=None, end=None, search="", limit=None, offset=0):
    query = select(Vulnerability).order_by(Vulnerability.id)
    if start:
        query = query.where(Vulnerability.first_seen >= start)
    if end:
        query = query.where(Vulnerability.first_seen < end)
    if search:
        idquery = select(Identifier.vulnerability_id).where(
            Identifier.value.ilike("%" + search + "%")
        )
        query = query.where(
            Vulnerability.title.ilike("%" + search + "%")
            | Vulnerability.id.in_(idquery)
        )
    if limit:
        query = query.limit(limit).offset(offset)
    vulns = list(s.scalars(query))
    ids = [v.id for v in vulns]
    identifiers = defaultdict(list)
    facts = defaultdict(lambda: defaultdict(list))
    if ids:
        for item in s.scalars(
            select(Identifier).where(Identifier.vulnerability_id.in_(ids))
        ):
            identifiers[item.vulnerability_id].append(item)
        for item in s.scalars(select(Fact).where(Fact.vulnerability_id.in_(ids))):
            facts[item.vulnerability_id][item.kind].append(item.data)
    for v in vulns:
        f = facts[v.id]
        at = f["attribution"]
        products = f["product"]
        sev = f["severity"]
        patches = f["remediation"]
        scores = [float(a["score"]) for a in sev if a.get("score") is not None]
        ranked = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        epss = max(f["epss"], key=lambda x: x["date"], default={})
        row = dict.fromkeys(COLUMNS)
        row.update(
            {
                "ID": v.id,
                "First Seen": v.first_seen.isoformat(),
                "CVE ID": join(x.value for x in identifiers[v.id] if x.kind == "CVE"),
                "GHSA ID": join(x.value for x in identifiers[v.id] if x.kind == "GHSA"),
                "Vulnerability Title": v.title,
                "State": v.state,
                "AI Organization": join(a.get("organization") for a in at),
                "AI Use Confirmed": any(
                    a.get("ai_use_confirmed")
                    or a.get("category") in ("autonomous", "human_assisted")
                    for a in at
                ),
                "AI Model": join(a.get("model") for a in at),
                "Discovery Attribution": join(a.get("category") for a in at)
                or "unknown",
                "Attribution Evidence URL": join(a.get("evidence_url") for a in at),
                "Vendor": join(p.get("vendor") for p in products),
                "Affected Product": join(p.get("product") for p in products),
                "Affected Versions": join(
                    str(p.get("versions")) for p in products if p.get("versions")
                ),
                "Fixed Version": join(
                    x for p in products for x in p.get("fixed_versions", [])
                ),
                "CVSS Score": max(scores) if scores else None,
                "CVSS Severity": max(
                    (str(a.get("severity", "unknown")).lower() for a in sev),
                    key=lambda x: ranked.get(x, 0),
                    default="unknown",
                ),
                "EPSS Score": epss.get("probability"),
                "EPSS Percentile": epss.get("percentile"),
                "CISA KEV": any(a.get("present") for a in f["kev"])
                if f["kev"]
                else None,
                "CWE": join(a.get("cwe") for a in f["classification"]),
                "Vulnerability Category": join(
                    a.get("category") for a in f["classification"]
                ),
                "Publication Date": v.published,
                "Discovery Date": v.discovered,
                "Patch Available": True
                if any(p.get("patch_available") is True for p in patches)
                else (
                    False
                    if any(p.get("patch_available") is False for p in patches)
                    else None
                ),
                "Remediation": join(p.get("text") for p in patches),
                "Source URL": join(a.get("url") for a in f["reference"]),
            }
        )
        row["Operational Priority"], row["Priority Explanation"] = priority(
            row, settings.priority_config
        )
        yield row


def batched_records(s, settings, **kwargs):
    offset = 0
    while True:
        batch = list(records(s, settings, limit=500, offset=offset, **kwargs))
        yield from batch
        if len(batch) < 500:
            break
        offset += 500


def metrics(s):
    total = s.scalar(select(func.count()).select_from(Vulnerability))
    confirmed = (
        select(Fact.vulnerability_id)
        .where(
            Fact.kind == "attribution",
            (
                Fact.data["category"].as_string().in_(["autonomous", "human_assisted"])
                | Fact.data["ai_use_confirmed"].as_boolean().is_(True)
            ),
        )
        .distinct()
    )
    return {
        "total_unique_vulnerabilities": total,
        "confirmed_ai_discoveries": s.scalar(
            select(func.count()).select_from(confirmed.subquery())
        ),
        "unique_cves": s.scalar(
            select(func.count()).select_from(Identifier).where(Identifier.kind == "CVE")
        ),
        "unique_ghsas": s.scalar(
            select(func.count())
            .select_from(Identifier)
            .where(Identifier.kind == "GHSA")
        ),
    }


def health(s):
    rows = []
    for source in s.scalars(select(Source).order_by(Source.name)):
        run = s.scalar(
            select(Run)
            .where(Run.source == source.name)
            .order_by(Run.id.desc())
            .limit(1)
        )
        stale = source.last_success is None or now() - source.last_success > timedelta(
            hours=48
        )
        warnings = []
        if stale:
            warnings.append("Stale or never synchronized")
        if source.checkpoint.get("cve") or source.checkpoint.get("identifier"):
            warnings.append("Enrichment sweep incomplete; resume on next run")
        if source.name == "cve":
            unavailable = s.scalar(
                select(func.count())
                .select_from(Fact)
                .where(
                    Fact.kind == "availability",
                    Fact.source == "cve",
                    Fact.data["public_record"].as_boolean().is_(False),
                )
            )
            if unavailable:
                warnings.append(f"{unavailable} identifiers have no public CVE record")
        rows.append(
            {
                "Source": source.name,
                "Status": source.status,
                "Last Successful Sync": str(source.last_success or "never"),
                "Last Attempt": str(source.last_attempt or "never"),
                "Records Processed": run.processed if run else 0,
                "New Records": run.created if run else 0,
                "Updated Records": run.updated if run else 0,
                "Failures": run.failed if run else 0,
                "Request Errors": run.errors if run else 0,
                "Rate Limits": run.rate_limits if run else 0,
                "Completeness Warning": "; ".join(warnings),
                "Error": source.error,
            }
        )
    return rows
