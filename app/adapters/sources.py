"""Adapters yield bounded pages; checkpoint advances only after a committed page."""

from abc import ABC, abstractmethod
import httpx
from dataclasses import dataclass
from pathlib import Path
from datetime import timedelta
from sqlalchemy import select
from app.database.models import Identifier, now
from app.domain import Record, credits_claim, cvss_assessments

ANT_URL = "https://red.anthropic.com/2026/cvd/"


@dataclass
class Page:
    records: list[Record]
    checkpoint: dict


class Adapter(ABC):
    name = ""
    endpoint = ""

    def __init__(self, http, settings, sessions):
        self.http, self.settings, self.sessions = http, settings, sessions

    def connectivity(self):
        self.http.get(self.endpoint)
        return True

    def health(self):
        return {
            "request_errors": self.http.errors,
            "rate_limits": self.http.rate_limits,
        }

    @abstractmethod
    def normalize(self, raw): ...
    @abstractmethod
    def fetch(self, checkpoint, backfill=False): ...
    def synchronize(self, checkpoint, backfill=False):
        yield from self.fetch(checkpoint, backfill)


class Anthropic(Adapter):
    name = "anthropic"
    endpoint = ANT_URL + "data/ledger.json"

    def normalize(self, r):
        if not isinstance(r.get("revealed"), bool) or not r.get("hash"):
            raise ValueError("Unsupported Anthropic ledger schema")
        if not r["revealed"]:
            return Record(r["hash"], r, sealed=True, url=ANT_URL)
        corrections = set(
            r.get("corrected_cve_ids", []) + r.get("corrected_ghsa_ids", [])
        )
        ids = [
            i
            for i in r.get("cve_ids", []) + r.get("ghsa_ids", [])
            if i not in corrections
        ]
        assessments = []
        for k, assessor in [
            ("claude_severity", "Claude"),
            ("vendor_severity", "External triage"),
            ("maintainer_severity", "Maintainer"),
        ]:
            if r.get(k):
                assessments.append(
                    {"key": k, "assessor": assessor, "severity": r[k], "score": None}
                )
        # The program states models find candidates and humans triage. Individual
        # automation and model identity are not established by a ledger membership.
        attr = {
            "organization": "Anthropic",
            "model": None,
            "category": "unknown",
            "ai_use_confirmed": True,
            "verification": "primary_program_statement",
            "evidence_url": ANT_URL,
            "claim": "The program describes Claude models finding candidates followed by human triage and review; individual model and autonomy are unspecified.",
            "published": None,
        }
        facts = {
            "severity": assessments,
            "attribution": [attr],
            "product": [
                {
                    "vendor": None,
                    "product": r.get("project"),
                    "versions": [],
                    "fixed_versions": [],
                }
            ],
            "remediation": [
                {
                    "patch_available": True if r.get("patched") else None,
                    "text": None,
                    "patched_at": r.get("corrected_patched_at") or r.get("patched_at"),
                }
            ],
            "classification": [{"cwe": None, "category": r.get("bug_class")}],
            "reference": [
                {"url": ANT_URL, "finding_id": r.get("ant_id"), "commitment": r["hash"]}
            ],
        }
        return Record(
            r["hash"],
            r,
            ids,
            title=r.get("public_title") or r.get("ant_id") or r.get("project"),
            discovered=r.get("discovered_on"),
            published=r.get("revealed_at") or None,
            state="withdrawn" if r.get("withdrawn") else r.get("status"),
            facts=facts,
            url=ANT_URL,
        )

    def fetch(self, checkpoint, backfill=False):
        import re

        completed = list(checkpoint.get("archives_completed", []))
        archives = self.settings.anthropic_snapshots.split(",") if backfill else []
        for snapshot in [v.strip() for v in archives if v.strip()] + ["current"]:
            if snapshot != "current" and snapshot in completed:
                continue
            if snapshot != "current" and not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}-\d{4}", snapshot
            ):
                raise ValueError("Invalid public snapshot name")
            base = (
                ANT_URL if snapshot == "current" else ANT_URL + f"snapshots/{snapshot}/"
            )
            payload = self.http.get(base + "data/payload.json")
            data = self.http.get(base + "data/ledger.json")
            if not isinstance(data, list) or not isinstance(payload, dict):
                raise ValueError("Unsupported Anthropic snapshot schema")
            titles = {}
            for advisory in payload.get("cve_records", []) + payload.get(
                "ghsa_records", []
            ):
                for finding in advisory.get("findings", []):
                    if finding.get("ant_id") and finding.get("title"):
                        titles[finding["ant_id"]] = finding["title"]
            for offset in range(0, len(data), 100):
                rows = []
                for r in data[offset : offset + 100]:
                    r = dict(r)
                    r["source_snapshot_at"] = payload.get("as_of")
                    r["manifest_sha3"] = payload.get("manifest_sha3")
                    r["snapshot_url"] = base
                    if r.get("revealed"):
                        r["public_title"] = titles.get(r.get("ant_id"))
                    rec = self.normalize(r)
                    if not rec.sealed:
                        rec.facts["snapshot"] = [
                            {
                                "date": payload.get("as_of"),
                                "url": base,
                                "manifest_sha3": payload.get("manifest_sha3"),
                            }
                        ]
                    rows.append(rec)
                yield Page(
                    rows,
                    {"archives_completed": completed, "observed": now().isoformat()},
                )
            if snapshot != "current":
                completed = completed + [snapshot]
                yield Page([], {"archives_completed": completed})


class CVE(Adapter):
    name = "cve"
    endpoint = (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
    )

    def attributions(self, r):
        containers = r.get("containers", {})
        sources = [containers.get("cna", {}), *containers.get("adp", [])]
        credits = "\n".join(
            str(c.get("value", ""))
            for source in sources
            for c in source.get("credits", [])
        )
        cve = r["cveMetadata"]["cveId"]
        return credits_claim(
            credits,
            f"https://www.cve.org/CVERecord?id={cve}",
            r["cveMetadata"].get("datePublished"),
        )

    def normalize(self, r):
        metadata = r["cveMetadata"]
        cve = metadata["cveId"]
        url = f"https://www.cve.org/CVERecord?id={cve}"
        cna = r.get("containers", {}).get("cna", {})
        descriptions = cna.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), None
        )
        attrs = self.attributions(r)
        facts = {
            "availability": [{"public_record": True}],
            "severity": cvss_assessments(cna.get("metrics", [])),
            "attribution": attrs,
            "product": [
                {
                    "vendor": a.get("vendor"),
                    "product": a.get("product"),
                    "versions": a.get("versions", []),
                    "fixed_versions": [],
                }
                for a in cna.get("affected", [])
            ],
            "reference": [
                {"url": x["url"]} for x in cna.get("references", []) if x.get("url")
            ],
            "classification": [
                {"cwe": d.get("cweId"), "category": d.get("description")}
                for p in cna.get("problemTypes", [])
                for d in p.get("descriptions", [])
            ],
            "remediation": [
                {
                    "patch_available": None,
                    "text": "\n".join(
                        x.get("value", "") for x in cna.get("solutions", [])
                    )
                    or None,
                }
            ],
        }
        return Record(
            cve,
            r,
            [cve],
            cna.get("title"),
            description,
            metadata.get("datePublished"),
            state=metadata.get("state", "PUBLISHED").lower(),
            facts=facts,
            create=bool(attrs),
            url=url,
        )

    def fetch(self, checkpoint, backfill=False):
        if backfill:
            from app.adapters.history import history_pages

            yield from history_pages(self, checkpoint)
            return
        saved = {k: v for k, v in checkpoint.items() if k != "cve"}
        with self.sessions() as s:
            ids = list(
                s.scalars(
                    select(Identifier.value)
                    .where(Identifier.kind == "CVE")
                    .order_by(Identifier.value)
                )
            )
        # Refresh all tracked CVEs, checkpoint each completed record; restart rotates
        # to first after a fully successful pass. No corpus downloaded into memory.
        cursor = checkpoint.get("cve", "")
        remaining = [x for x in ids if x > cursor]
        for cve in remaining[: self.settings.enrichment_limit]:
            year, number = cve.split("-")[1:]
            bucket = number[:-3] + "xxx"
            url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
            try:
                raw = self.http.get(url)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404:
                    raise
                # Public assignment may precede publication in cvelistV5. Retain
                # an availability observation, advance, and retry on next sweep.
                yield Page(
                    [
                        Record(
                            cve + ":availability",
                            {"cve": cve, "public_record": False},
                            [cve],
                            facts={
                                "availability": [{"public_record": False, "url": url}]
                            },
                            create=False,
                        )
                    ],
                    {**saved, "cve": cve},
                )
                continue
            yield Page([self.normalize(raw)], {**saved, "cve": cve})
        if len(remaining) <= self.settings.enrichment_limit:
            yield Page([], saved)


class GHSA(Adapter):
    name = "ghsa"
    endpoint = "https://api.github.com/advisories"

    def connectivity(self):
        self.http.get(self.endpoint, {"per_page": 1})
        return True

    def normalize(self, r):
        ids = [
            i["value"]
            for i in r.get("identifiers", [])
            if i.get("type") in ("CVE", "GHSA")
        ]
        if r["ghsa_id"] not in ids:
            ids.append(r["ghsa_id"])
        facts = {
            "product": [],
            "severity": [
                {
                    "severity": r.get("severity", "unknown"),
                    "score": (r.get("cvss") or {}).get("score"),
                    "vector": (r.get("cvss") or {}).get("vector_string"),
                    "assessor": "GitHub",
                }
            ],
            "reference": [{"url": r["html_url"]}],
            "remediation": [],
            "classification": [
                {"cwe": x.get("cwe_id"), "category": x.get("name")}
                for x in r.get("cwes", [])
            ],
        }
        for v in r.get("vulnerabilities", []):
            fix = v.get("first_patched_version")
            if isinstance(fix, dict):
                fix = fix.get("identifier")
            facts["product"].append(
                {
                    "vendor": None,
                    "product": v["package"]["name"],
                    "ecosystem": v["package"]["ecosystem"],
                    "versions": [v.get("vulnerable_version_range")],
                    "fixed_versions": [fix] if fix else [],
                }
            )
            facts["remediation"].append(
                {
                    "patch_available": True if fix else None,
                    "text": f"Upgrade to {fix}" if fix else None,
                }
            )
        return Record(
            r["ghsa_id"],
            r,
            ids,
            r.get("summary"),
            r.get("description"),
            r.get("published_at"),
            state="withdrawn" if r.get("withdrawn_at") else "published",
            facts=facts,
            create=False,
            url=r["html_url"],
        )

    def fetch(self, checkpoint, backfill=False):
        with self.sessions() as s:
            ids = list(
                s.scalars(
                    select(Identifier.value)
                    .where(Identifier.kind.in_(["CVE", "GHSA"]))
                    .order_by(Identifier.value)
                )
            )
        cursor = checkpoint.get("identifier", checkpoint.get("cve", ""))
        remaining = [x for x in ids if x > cursor]
        # Reserve some unauthenticated quota for health/manual requests. Public
        # mode remains resumable instead of demanding credentials.
        budget = (
            self.settings.enrichment_limit
            if self.settings.github_token
            else min(40, self.settings.enrichment_limit)
        )
        for public_id in remaining[:budget]:
            if public_id.startswith("GHSA-"):
                raw = self.http.get(self.endpoint + "/" + public_id)
                yield Page([self.normalize(raw)], {"identifier": public_id})
                continue
            page = 1
            while True:
                rows = self.http.get(
                    self.endpoint, {"cve_id": public_id, "per_page": 100, "page": page}
                )
                if not isinstance(rows, list):
                    raise ValueError("Unexpected GHSA response")
                yield Page(
                    [self.normalize(r) for r in rows],
                    {"identifier": public_id}
                    if len(rows) < 100
                    else {"identifier": cursor},
                )
                if len(rows) < 100:
                    break
                page += 1
        if len(remaining) <= budget:
            yield Page([], {})


class KEV(Adapter):
    name = "kev"
    endpoint = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

    def normalize(self, r):
        return Record(
            r["cveID"],
            r,
            [r["cveID"]],
            facts={"kev": [{"present": True, **r}]},
            create=False,
            url=self.endpoint,
        )

    def fetch(self, checkpoint, backfill=False):
        data = self.http.get(self.endpoint)
        catalog = {r["cveID"]: r for r in data["vulnerabilities"]}
        with self.sessions() as s:
            ids = list(
                s.scalars(select(Identifier.value).where(Identifier.kind == "CVE"))
            )
        for start in range(0, len(ids), 100):
            records = [
                self.normalize(catalog[c])
                if c in catalog
                else Record(
                    c,
                    {"cveID": c, "present": False},
                    [c],
                    facts={
                        "kev": [
                            {
                                "present": False,
                                "catalog_version": data.get("catalogVersion"),
                            }
                        ]
                    },
                    create=False,
                )
                for c in ids[start : start + 100]
            ]
            yield Page(records, {"version": data.get("catalogVersion")})


class EPSS(Adapter):
    name = "epss"
    endpoint = "https://api.first.org/data/v1/epss"

    def normalize(self, r):
        probability, percentile = float(r["epss"]), float(r["percentile"])
        if not (0 <= probability <= 1 and 0 <= percentile <= 1):
            raise ValueError("Invalid EPSS probability")
        return Record(
            r["cve"] + ":" + r["date"],
            r,
            [r["cve"]],
            facts={
                "epss": [
                    {
                        "probability": probability,
                        "percentile": percentile,
                        "date": r["date"],
                        "cve": r["cve"],
                    }
                ]
            },
            create=False,
            url=self.endpoint,
        )

    def fetch(self, checkpoint, backfill=False, date=None):
        with self.sessions() as s:
            ids = list(
                s.scalars(
                    select(Identifier.value)
                    .where(Identifier.kind == "CVE")
                    .order_by(Identifier.value)
                )
            )
        if len(ids) >= self.settings.epss_bulk_threshold:
            score_date = date
            if not score_date and ids:
                probe = self.http.get(self.endpoint, {"cve": ids[0], "limit": 1})
                score_date = (
                    probe["data"][0]["date"]
                    if probe.get("data")
                    else (now().date() - timedelta(days=1)).isoformat()
                )
            yield from self.bulk(ids, score_date)
            return
        for start in range(0, len(ids), 50):
            params = {"cve": ",".join(ids[start : start + 50]), "limit": 100}
            if date:
                params["date"] = date
            data = self.http.get(self.endpoint, params)
            yield Page(
                [self.normalize(r) for r in data["data"]],
                {"date": date or now().date().isoformat()},
            )

    def bulk(self, ids, score_date):
        """Official FIRST-linked dated CSV archive; cache once per score date."""
        import csv
        import gzip
        import os
        import tempfile
        from datetime import date as Date

        day = Date.fromisoformat(score_date)
        folder = self.settings.cache_dir / "epss"
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = folder / f"epss_scores-{day}.csv.gz"
        if not path.exists():
            url = f"https://raw.githubusercontent.com/empiricalsec/epss_scores/main/{day.year}/epss_scores-{day}.csv.gz"
            data = self.http.get(url, binary=True)
            with tempfile.NamedTemporaryFile(dir=folder, delete=False) as tmp:
                tmp.write(data)
                temp_path = Path(tmp.name)
            try:
                os.chmod(temp_path, 0o600)
                os.replace(temp_path, path)
            finally:
                temp_path.unlink(missing_ok=True)
        wanted = set(ids)
        batch = []
        # Rows are streamed from gzip, not materialized as a full score table.
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            size = 0

            def lines():
                nonlocal size
                for line in handle:
                    size += len(line)
                    if size > 256 * 1024 * 1024:
                        raise ValueError("Expanded EPSS CSV exceeds safety limit")
                    if not line.startswith("#"):
                        yield line

            for row in csv.DictReader(lines()):
                if row.get("cve") in wanted:
                    row["date"] = str(day)
                    batch.append(self.normalize(row))
                    if len(batch) >= 100:
                        yield Page(batch, {"date": str(day), "mode": "bulk"})
                        batch = []
        if batch:
            yield Page(batch, {"date": str(day), "mode": "bulk"})

    def history(self, start, end):
        if (end - start).days > 365:
            raise ValueError("Backfill at most 365 days per command")
        day = start
        while day <= end:
            yield from self.fetch({}, date=day.isoformat())
            day += timedelta(days=1)


class Frontier(Adapter):
    name = "frontier"
    endpoint = (
        "https://api.github.com/repos/securin-public/frontier-ai-cve-tracker/license"
    )

    def normalize(self, raw):
        raise RuntimeError(
            "Ingestion disabled pending content license and schema review"
        )

    def fetch(self, checkpoint, backfill=False):
        self.http.get(self.endpoint)
        raise RuntimeError(
            "Frontier ingestion disabled: repository content license has not been approved; see docs/sources.md"
        )
        yield
