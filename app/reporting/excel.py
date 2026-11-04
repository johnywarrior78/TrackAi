"""Atomic XLSX export, independent checkpoints, bounded query batches."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit
import json
import os
import re
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.formatting.rule import CellIsRule
from openpyxl.cell import WriteOnlyCell
from sqlalchemy import select
from app.database.models import ReportRun, Change, Run, Fact, Vulnerability, now
from app.database.session import job_lock
from app.queries import COLUMNS, batched_records, health

MAX_ROWS = 1_048_576
MAX_TEXT = 32767


def safe(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, str):
        # Force strings and neutralize spreadsheet command/formula prefixes.
        value = re.sub(
            r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]",
            lambda m: f"\\u{ord(m.group()):04x}",
            value,
        )
        if value.lstrip(" \t\r\n\ufeff").startswith(
            ("=", "+", "-", "@")
        ) or value.startswith(("\t", "\r", "\n")):
            value = "'" + value
    return value


class Sheets:
    def __init__(self, book, title, columns, max_rows=MAX_ROWS):
        self.book, self.title, self.columns, self.max_rows = (
            book,
            title,
            columns,
            max_rows,
        )
        self.part = 0
        self.count = 0
        self.new()

    def new(self):
        self.part += 1
        suffix = f" {self.part}" if self.part > 1 else ""
        self.ws = self.book.create_sheet(self.title[: 31 - len(suffix)] + suffix)
        self.ws.freeze_panes = "A2"
        from openpyxl.utils import get_column_letter

        for i, col in enumerate(self.columns, 1):
            self.ws.column_dimensions[get_column_letter(i)].width = min(
                55, max(18, len(col) + 3)
            )
        self.ws.append([self.cell(col, header=True) for col in self.columns])
        self.count = 1

    def cell(self, value, header=False):
        value = safe(value)
        c = WriteOnlyCell(self.ws, value=value)
        if isinstance(value, str):
            c.data_type = "s"
        c.alignment = Alignment(vertical="top", wrap_text=True)
        if header:
            c.fill = PatternFill("solid", fgColor="17365D")
            c.font = Font(color="FFFFFF", bold=True)
        elif isinstance(value, str) and value in ("critical", "high", "P1", "P2"):
            c.fill = PatternFill(
                "solid", fgColor="FFC7CE" if value in ("critical", "P1") else "FFEB9C"
            )
        if isinstance(value, str) and len(value) < 2048:
            try:
                p = urlsplit(value)
            except ValueError:
                p = urlsplit("")
            if (
                p.scheme in ("https", "http")
                and p.hostname
                and not p.username
                and not any(c.isspace() for c in value)
            ):
                c.hyperlink = value
                c.font = Font(color="0563C1", underline="single")
        if isinstance(value, float):
            c.number_format = "0.0000"
        return c

    def append(self, row):
        if self.count >= self.max_rows:
            self.finish()
            self.new()
        values = [row.get(c) for c in self.columns]
        # Oversized source text is losslessly split into numbered continuation
        # rows. The main cell references that location rather than truncating.
        for i, v in enumerate(values):
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False, default=str)
                values[i] = v
            if isinstance(v, str) and len(safe(v)) > MAX_TEXT:
                overflow = getattr(self.book, "_aivi_overflow", None)
                if overflow is None:
                    overflow = Sheets(
                        self.book,
                        "Long Text",
                        ["Origin Sheet", "Origin Row", "Column", "Part", "Text"],
                    )
                    self.book._aivi_overflow = overflow
                reference = f"{self.ws.title} row {self.count + 1} {self.columns[i]}"
                for part, offset in enumerate(range(0, len(v), 5000), 1):
                    overflow.append(
                        {
                            "Origin Sheet": self.ws.title,
                            "Origin Row": self.count + 1,
                            "Column": self.columns[i],
                            "Part": part,
                            "Text": v[offset : offset + 5000],
                        }
                    )
                values[i] = f"Full text in Long Text: {reference} ({len(v)} characters)"
        cells = []
        for column, value in zip(self.columns, values):
            if column in (
                "First Seen",
                "Publication Date",
                "Discovery Date",
                "Changed At",
            ) and isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value)
                    if value.tzinfo:
                        value = value.astimezone(timezone.utc).replace(tzinfo=None)
                except ValueError:
                    pass
            cell = self.cell(value)
            if isinstance(value, datetime):
                cell.number_format = "yyyy-mm-dd hh:mm:ss"
            cells.append(cell)
        self.ws.append(cells)
        self.count += 1

    def finish(self):
        from openpyxl.utils import get_column_letter

        self.ws.auto_filter.ref = (
            f"A1:{get_column_letter(len(self.columns))}{self.count}"
        )
        for i, col in enumerate(self.columns, 1):
            if (
                col in ("CVSS Score", "EPSS Score", "EPSS Percentile")
                and self.count > 1
            ):
                c = get_column_letter(i)
                self.ws.conditional_formatting.add(
                    f"{c}2:{c}{self.count}",
                    CellIsRule(
                        operator="greaterThanOrEqual",
                        formula=["7" if col == "CVSS Score" else "0.1"],
                        fill=PatternFill("solid", fgColor="FFEB9C"),
                    ),
                )


def generate(engine, sessions, settings, start=None, end=None):
    custom = start is not None or end is not None
    with job_lock(engine, sessions, "report"), job_lock(engine, sessions, "collection"):
        cutoff = now()
        with sessions.begin() as s:
            previous = s.scalar(
                select(ReportRun)
                .where(ReportRun.status == "success", ReportRun.custom.is_(False))
                .order_by(ReportRun.id.desc())
                .limit(1)
            )
            checkpoint = previous.checkpoint if previous else None
            baseline = not custom and checkpoint is None
            run = ReportRun(checkpoint=cutoff, baseline=baseline, custom=custom)
            s.add(run)
            s.flush()
            run_id = run.id
        settings.report_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = f"AI_Vulnerability_Intelligence_{cutoff.date()}"
        path = settings.report_dir / (
            name + (f"_custom_{run_id}" if custom else "") + ".xlsx"
        )
        if path.exists():
            path = settings.report_dir / (name + f"_{run_id}.xlsx")
        temp = None
        try:
            book = Workbook(write_only=True)
            summary = Sheets(book, "Executive Summary", ["Metric", "Value"])
            new = Sheets(book, "New Vulnerabilities", COLUMNS)
            updated = Sheets(
                book,
                "Updated Vulnerabilities",
                ["ID", "Changed At", "Source", "Field", "Previous", "Current"],
            )
            critical = Sheets(book, "Critical and High", COLUMNS)
            kev = Sheets(book, "Known Exploited", COLUMNS)
            product = Sheets(
                book,
                "Product Summary",
                [
                    "Vendor",
                    "Product",
                    "Total findings",
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "KEV count",
                    "Average EPSS",
                    "Patch availability count",
                ],
            )
            ai = Sheets(
                book,
                "AI Discovery Summary",
                [
                    "AI Organization",
                    "AI Model",
                    "Autonomous",
                    "Human Assisted",
                    "Credited Only",
                    "Unverified",
                    "Unknown",
                ],
            )
            collection = Sheets(
                book,
                "Collection Health",
                [
                    "Source",
                    "Status",
                    "Last Successful Sync",
                    "Last Attempt",
                    "Records Processed",
                    "New Records",
                    "Updated Records",
                    "Failures",
                    "Request Errors",
                    "Rate Limits",
                    "Completeness Warning",
                    "Error",
                ],
            )
            counts = Counter(
                {
                    k: 0
                    for k in (
                        "New vulnerabilities",
                        "Updated vulnerabilities",
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "unknown",
                        "CISA KEV matches",
                        "Confirmed AI discoveries",
                    )
                }
            )
            vendors = Counter()
            products = defaultdict(
                lambda: {
                    "ids": set(),
                    "sev": Counter(),
                    "kev": set(),
                    "epss": {},
                    "patch": set(),
                }
            )
            ai_counts = defaultdict(lambda: defaultdict(set))
            with sessions() as s:
                # Fixed cutoff prevents records observed during generation leaking into checkpoint.
                for row in batched_records(s, settings, end=cutoff):
                    if start and datetime.fromisoformat(row["First Seen"]) < start:
                        continue
                    if end and datetime.fromisoformat(row["First Seen"]) >= end:
                        continue
                    vid = row["ID"]
                    counts["Inventory"] += 1
                    counts[row["CVSS Severity"]] += 1
                    if row["CISA KEV"]:
                        counts["CISA KEV matches"] += 1
                        kev.append(row)
                    if row["CVSS Severity"] in ("critical", "high"):
                        critical.append(row)
                    if not baseline and (
                        custom or datetime.fromisoformat(row["First Seen"]) > checkpoint
                    ):
                        new.append(row)
                        counts["New vulnerabilities"] += 1
                    if row["AI Use Confirmed"]:
                        counts["Confirmed AI discoveries"] += 1
                    # Group actual product facts rather than splitting display strings.
                    seen = set()
                    for fact in s.scalars(
                        select(Fact).where(
                            Fact.vulnerability_id == vid, Fact.kind == "product"
                        )
                    ):
                        p = fact.data
                        key = (
                            p.get("vendor") or "Unknown",
                            p.get("product") or "Unknown",
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        group = products[key]
                        group["ids"].add(vid)
                        group["sev"][row["CVSS Severity"]] += 1
                        vendors[key[0]] += 1
                        if row["CISA KEV"]:
                            group["kev"].add(vid)
                        if row["EPSS Score"] is not None:
                            group["epss"][vid] = row["EPSS Score"]
                        if row["Patch Available"] is True:
                            group["patch"].add(vid)
                    for fact in s.scalars(
                        select(Fact).where(
                            Fact.vulnerability_id == vid, Fact.kind == "attribution"
                        )
                    ):
                        a = fact.data
                        ai_counts[
                            (
                                a.get("organization") or "Unknown",
                                a.get("model") or "Unspecified",
                            )
                        ][a["category"]].add(vid)
                changed = set()
                q = (
                    select(Change)
                    .join(Vulnerability, Change.vulnerability_id == Vulnerability.id)
                    .where(Change.at <= cutoff)
                    .order_by(Change.id)
                )
                lower = start if custom else checkpoint
                if lower:
                    q = q.where(Change.at > lower, Vulnerability.first_seen <= lower)
                if end:
                    q = q.where(Change.at < end)
                if not baseline:
                    for ch in s.scalars(q).yield_per(500):
                        updated.append(
                            {
                                "ID": ch.vulnerability_id,
                                "Changed At": ch.at.isoformat(),
                                "Source": ch.source,
                                "Field": ch.field,
                                "Previous": ch.previous,
                                "Current": ch.current,
                            }
                        )
                        changed.add(ch.vulnerability_id)
                counts["Updated vulnerabilities"] = len(changed)
                summary.append(
                    {"Metric": "Report date UTC", "Value": cutoff.isoformat()}
                )
                summary.append(
                    {
                        "Metric": "Report mode",
                        "Value": "BASELINE — inventory at first observation; not newly discovered today"
                        if baseline
                        else (
                            "CUSTOM — first-seen date range"
                            if custom
                            else "Daily changes since previous successful report"
                        ),
                    }
                )
                summary.append(
                    {
                        "Metric": "Previous successful checkpoint",
                        "Value": checkpoint.isoformat() if checkpoint else "None",
                    }
                )
                last = s.scalar(
                    select(Run.finished)
                    .where(Run.status == "success")
                    .order_by(Run.finished.desc())
                    .limit(1)
                )
                summary.append(
                    {
                        "Metric": "Last successful collection",
                        "Value": str(last or "None"),
                    }
                )
                for key, value in counts.items():
                    summary.append({"Metric": key, "Value": value})
                for vendor, count in vendors.most_common(10):
                    summary.append({"Metric": f"Top vendor: {vendor}", "Value": count})
                for (vendor, p), g in sorted(
                    products.items(), key=lambda x: len(x[1]["ids"]), reverse=True
                ):
                    product.append(
                        {
                            "Vendor": vendor,
                            "Product": p,
                            "Total findings": len(g["ids"]),
                            "Critical": g["sev"]["critical"],
                            "High": g["sev"]["high"],
                            "Medium": g["sev"]["medium"],
                            "Low": g["sev"]["low"],
                            "KEV count": len(g["kev"]),
                            "Average EPSS": sum(g["epss"].values()) / len(g["epss"])
                            if g["epss"]
                            else None,
                            "Patch availability count": len(g["patch"]),
                        }
                    )
                for (org, model), g in ai_counts.items():
                    ai.append(
                        {
                            "AI Organization": org,
                            "AI Model": model,
                            "Autonomous": len(g["autonomous"]),
                            "Human Assisted": len(g["human_assisted"]),
                            "Credited Only": len(g["credited_only"]),
                            "Unverified": len(g["unverified"]),
                            "Unknown": len(g["unknown"]),
                        }
                    )
                for h in health(s):
                    collection.append(h)
                    if h["Completeness Warning"]:
                        summary.append(
                            {
                                "Metric": f"Freshness: {h['Source']}",
                                "Value": h["Completeness Warning"],
                            }
                        )
            for sheet in (
                summary,
                new,
                updated,
                critical,
                kev,
                product,
                ai,
                collection,
            ):
                sheet.finish()
            with NamedTemporaryFile(
                dir=settings.report_dir, suffix=".xlsx", delete=False
            ) as f:
                temp = Path(f.name)
            overflow = getattr(book, "_aivi_overflow", None)
            if overflow:
                overflow.finish()
            book.save(temp)
            os.chmod(temp, 0o600)
            os.replace(temp, path)
            with sessions.begin() as s:
                run = s.get(ReportRun, run_id)
                run.status = "success"
                run.path = str(path.resolve())
            return path
        except Exception as exc:
            if temp:
                temp.unlink(missing_ok=True)
            with sessions.begin() as s:
                run = s.get(ReportRun, run_id)
                run.status = "failure"
                run.error = type(exc).__name__
            raise
