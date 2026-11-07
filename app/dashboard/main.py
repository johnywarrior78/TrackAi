"""Database-backed Streamlit dashboard. No raw source HTML is rendered."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pandas as pd
import streamlit as st
from sqlalchemy import select, func
from app.config import Settings
from app.database.session import connect
from app.database.models import (
    Vulnerability,
    Identifier,
    Fact,
    Change,
    SourceRecord,
    Snapshot,
    ScoreHistory,
    Metric,
    ReportRun,
    now,
)
from app.queries import records, metrics, health
from app.reporting.excel import generate, safe

st.set_page_config(
    page_title="AI Vulnerability Intelligence", page_icon="🛡️", layout="wide"
)
settings = Settings()


@st.cache_resource
def database(url):
    return connect(url)


engine, sessions = database(settings.database_url)
st.title("AI Vulnerability Intelligence")
st.caption("Evidence, exposure and remediation · UTC · locally hosted")
page = st.sidebar.radio(
    "Workspace",
    [
        "Executive Overview",
        "Vulnerability Explorer",
        "Vulnerability Details",
        "AI Research Landscape",
        "Historical Analytics",
        "Source Health",
        "Reporting",
    ],
)

with sessions() as s:
    try:
        total = s.scalar(select(func.count()).select_from(Vulnerability))
    except Exception:
        st.error(
            "Initialize the database with `aivi init-db` before opening the dashboard."
        )
        st.stop()
    if page == "Source Health":
        rows = health(s)
        st.dataframe(rows, width="stretch", hide_index=True)
        if not rows:
            st.info("No collection runs yet. Run aivi sync.")
        for r in rows:
            if r["Completeness Warning"]:
                st.warning(f"{r['Source']}: {r['Completeness Warning']}")
    elif page == "Vulnerability Details":
        vid = st.number_input("Internal finding ID", min_value=1, step=1)
        v = s.get(Vulnerability, int(vid))
        if not v:
            st.info("Select an existing ID from the explorer.")
            st.stop()
        st.subheader(v.title)
        st.write(v.description or "Description unavailable")
        st.write(
            {
                "First seen": str(v.first_seen),
                "Published": v.published,
                "Discovered": v.discovered,
                "State": v.state,
            }
        )
        st.write(
            "Identifiers",
            list(
                s.scalars(
                    select(Identifier.value).where(Identifier.vulnerability_id == vid)
                )
            ),
        )
        for kind in [
            "attribution",
            "severity",
            "product",
            "remediation",
            "classification",
            "reference",
            "kev",
        ]:
            st.subheader(kind.title())
            data = [
                f.data
                for f in s.scalars(
                    select(Fact).where(Fact.vulnerability_id == vid, Fact.kind == kind)
                )
            ]
            if data:
                st.json(data)
            else:
                st.caption("Unknown / not confirmed")
        st.subheader("EPSS history")
        points = [
            {"Date": h.date, "EPSS": h.probability, "CVE": h.cve}
            for h in s.scalars(
                select(ScoreHistory)
                .where(ScoreHistory.vulnerability_id == vid)
                .order_by(ScoreHistory.date)
            )
        ]
        if points:
            st.line_chart(pd.DataFrame(points), x="Date", y="EPSS")
        st.subheader("Change timeline")
        changes = list(
            s.scalars(
                select(Change)
                .where(Change.vulnerability_id == vid)
                .order_by(Change.id.desc())
                .limit(200)
            )
        )
        st.dataframe(
            [
                {
                    "At": str(c.at),
                    "Source": c.source,
                    "Field": c.field,
                    "Previous": str(c.previous),
                    "Current": str(c.current),
                }
                for c in changes
            ],
            hide_index=True,
        )
        st.subheader("Source record history (most recent 100 revisions)")
        q = (
            select(Snapshot)
            .join(SourceRecord, Snapshot.record_id == SourceRecord.id)
            .where(SourceRecord.vulnerability_id == vid)
            .order_by(Snapshot.id.desc())
            .limit(100)
        )
        for snap in s.scalars(q):
            with st.expander(f"Revision {snap.id} · observed {snap.observed_at}"):
                st.json(snap.payload)
    elif page == "Reporting":
        st.caption(
            "Custom ranges filter platform first-seen timestamps; end date is exclusive. Daily checkpoints are unaffected by custom exports."
        )
        custom = st.checkbox("Custom date range")
        a = b = None
        if custom:
            a = st.date_input("Start")
            b = st.date_input("End (exclusive)")
        if st.button("Generate Excel report"):
            if custom and a >= b:
                st.error("End must be later than start")
            else:
                start = (
                    datetime.combine(a, datetime.min.time(), tzinfo=timezone.utc)
                    if a
                    else None
                )
                end = (
                    datetime.combine(b, datetime.min.time(), tzinfo=timezone.utc)
                    if b
                    else None
                )
                try:
                    st.success(str(generate(engine, sessions, settings, start, end)))
                except Exception as exc:
                    st.error(
                        f"Report failed: {type(exc).__name__}. See report history."
                    )
        reports = list(
            s.scalars(select(ReportRun).order_by(ReportRun.id.desc()).limit(100))
        )
        st.dataframe(
            [
                {
                    "ID": r.id,
                    "Started": str(r.started),
                    "Status": r.status,
                    "Baseline": r.baseline,
                    "Custom": r.custom,
                    "Error": r.error,
                }
                for r in reports
            ],
            hide_index=True,
        )
        for r in reports:
            if r.status == "success" and r.path:
                path = Path(r.path).resolve()
                if (
                    path.is_relative_to(settings.report_dir.resolve())
                    and path.is_file()
                ):
                    st.download_button(
                        f"Download report {r.id}",
                        path.read_bytes(),
                        file_name=path.name,
                        key=f"report{r.id}",
                    )
    elif page == "Historical Analytics":
        st.info(
            "Snapshots represent actual platform observations. Backfills do not reconstruct past inventory states."
        )
        snapshots = [
            {"Date": m.day, **m.data}
            for m in s.scalars(select(Metric).order_by(Metric.day))
        ]
        if snapshots:
            st.line_chart(
                pd.DataFrame(snapshots),
                x="Date",
                y=["total_unique_vulnerabilities", "confirmed_ai_discoveries"],
            )
        history = list(
            s.execute(
                select(ScoreHistory.date, func.avg(ScoreHistory.probability))
                .group_by(ScoreHistory.date)
                .order_by(ScoreHistory.date)
            )
        )
        if history:
            st.line_chart(
                pd.DataFrame(history, columns=["Date", "Mean EPSS"]),
                x="Date",
                y="Mean EPSS",
            )
        changes = list(s.scalars(select(Change).order_by(Change.at.desc()).limit(1000)))
        st.dataframe(
            [
                {
                    "At": str(c.at),
                    "ID": c.vulnerability_id,
                    "Field": c.field,
                    "Source": c.source,
                }
                for c in changes
            ],
            hide_index=True,
        )
    else:
        # Bounded interactive result set; complete exports use reporting's batch iterator.
        search = st.sidebar.text_input("Search title, CVE or GHSA")
        page_number = st.sidebar.number_input(
            "Result page (500 records)", min_value=1, step=1
        )
        date_field = st.sidebar.selectbox(
            "Date field", ["Publication Date", "Discovery Date", "First Seen"]
        )
        date_start = date_end = None
        if st.sidebar.checkbox("Filter date range"):
            earliest = s.scalar(select(func.min(Vulnerability.published)))
            try:
                earliest = (
                    datetime.fromisoformat(earliest.replace("Z", "+00:00")).date()
                    if earliest
                    else now().date()
                )
            except ValueError:
                earliest = now().date()
            da = st.sidebar.date_input("From", value=earliest)
            db = st.sidebar.date_input("Through", value=now().date())
            if da > db:
                st.error("Start date must be on or before the end date.")
                st.stop()
            if date_field == "First Seen":
                date_start = datetime.combine(
                    da, datetime.min.time(), tzinfo=timezone.utc
                )
                date_end = datetime.combine(
                    db + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc
                )
            else:
                date_start = da.isoformat()
                date_end = (db + timedelta(days=1)).isoformat()
        data = list(
            records(
                s,
                settings,
                search=search,
                limit=500,
                offset=(page_number - 1) * 500,
                date_field=date_field,
                date_start=date_start,
                date_end=date_end,
            )
        )
        df = pd.DataFrame(data)
        st.caption(
            f"{total} unique tracked findings. Date filters search the full historical inventory before pagination. Other filters and charts apply to this 500-record page; use reports for full inventory exports."
        )
        if df.empty:
            st.info(
                "No matching records. Run aivi backfill to collect public disclosures."
            )
            st.stop()
        for column in [
            "AI Organization",
            "AI Model",
            "Discovery Attribution",
            "CVSS Severity",
            "Vendor",
            "Affected Product",
            "CWE",
            "Vulnerability Category",
            "Patch Available",
            "CISA KEV",
        ]:
            opts = sorted(df[column].dropna().astype(str).unique())
            selected = st.sidebar.multiselect(column, opts)
            if selected:
                df = df[df[column].astype(str).isin(selected)]
        cvss = st.sidebar.slider("CVSS range", 0.0, 10.0, (0.0, 10.0))
        epss = st.sidebar.slider("EPSS range", 0.0, 1.0, (0.0, 1.0))
        include_unknown = st.sidebar.checkbox("Include unknown scores", value=True)
        for col, bounds in [("CVSS Score", cvss), ("EPSS Score", epss)]:
            values = pd.to_numeric(df[col], errors="coerce")
            df = df[values.between(*bounds) | (values.isna() & include_unknown)]
        if page == "Vulnerability Explorer":
            st.dataframe(df, width="stretch", hide_index=True)
            clean = df.map(safe)
            st.download_button(
                "Download filtered page CSV",
                clean.to_csv(index=False).encode(),
                file_name="findings.csv",
                mime="text/csv",
            )
            st.caption(
                "Excel export and full inventory exports are available on Reporting."
            )
        elif page == "AI Research Landscape":
            st.warning(
                "Counts reflect disclosure coverage and attribution evidence; they do not measure model research capability. Model identity may be unspecified."
            )
            st.bar_chart(
                df.groupby(["AI Organization", "Discovery Attribution"])
                .size()
                .unstack(fill_value=0)
            )
            st.bar_chart(
                df.groupby(["AI Model", "CVSS Severity"]).size().unstack(fill_value=0)
            )
            st.dataframe(
                df[
                    [
                        "AI Organization",
                        "AI Model",
                        "Discovery Attribution",
                        "Attribution Evidence URL",
                    ]
                ],
                hide_index=True,
            )
        else:
            global_metrics = metrics(s)
            cols = st.columns(4)
            for col, (name, value) in zip(cols, global_metrics.items()):
                col.metric(name.replace("_", " ").title(), value)
            confirmed = df["AI Use Confirmed"]
            kpis = {
                "Confirmed AI (filtered)": int(confirmed.sum()),
                "Autonomous": int(
                    df["Discovery Attribution"].str.contains("autonomous").sum()
                ),
                "Human assisted": int(
                    df["Discovery Attribution"].str.contains("human_assisted").sum()
                ),
                "Critical": int((df["CVSS Severity"] == "critical").sum()),
                "High": int((df["CVSS Severity"] == "high").sum()),
                "CVEs with patches": int(
                    ((df["CVE ID"] != "") & (df["Patch Available"] == True)).sum()
                ),
                "KEV findings": int((df["CISA KEV"] == True).sum()),
                "Average EPSS": pd.to_numeric(df["EPSS Score"], errors="coerce").mean(),
            }
            for i, (name, value) in enumerate(kpis.items()):
                if i % 4 == 0:
                    cols = st.columns(4)
                cols[i % 4].metric(
                    name, "Unknown" if pd.isna(value) else str(round(value, 4))
                )
            dates = pd.to_datetime(df["Discovery Date"], errors="coerce", utc=True)
            st.metric(
                "Discovered in last 7 days",
                int((dates >= now() - timedelta(days=7)).sum()),
            )
            pub = pd.to_datetime(df["Publication Date"], errors="coerce", utc=True)
            st.metric(
                "Published in last 30 days",
                int((pub >= now() - timedelta(days=30)).sum()),
            )
            with st.expander("KPI definitions"):
                st.write(
                    "Global counts use distinct internal findings and distinct identifiers. Confirmed AI use requires an explicit source claim; autonomous/human-assisted counts additionally require evidence of the discovery method. Human triage alone does not establish the discovery method. Severity is the highest published assessment; disagreement remains in details. Unknown scores are excluded from averages. Patch counts require an explicit positive source statement. Unrevealed ledger commitments are excluded from vulnerability counts."
                )
            for title, col in [
                ("Severity distribution", "CVSS Severity"),
                ("AI organizations", "AI Organization"),
                ("AI systems", "AI Model"),
                ("Top products", "Affected Product"),
                ("Vulnerability classes", "Vulnerability Category"),
                ("Attribution", "Discovery Attribution"),
                ("Patch availability", "Patch Available"),
            ]:
                st.subheader(title)
                st.bar_chart(
                    df[col].fillna("Unknown").astype(str).value_counts().head(10)
                )
            st.subheader("Disclosures over time")
            d = pub.dropna().dt.strftime("%Y-%m-%d").value_counts().sort_index()
            st.line_chart(d)
