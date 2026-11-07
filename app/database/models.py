from datetime import datetime, timezone
from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def now():
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            raise ValueError("Naive timestamp forbidden")
        return value

    def process_result_value(self, value, dialect):
        return (
            value.replace(tzinfo=timezone.utc)
            if value is not None and value.tzinfo is None
            else value
        )


class Base(DeclarativeBase):
    pass


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(Text, default="Unknown")
    description: Mapped[str | None] = mapped_column(Text)
    published: Mapped[str | None] = mapped_column(String(40), index=True)
    discovered: Mapped[str | None] = mapped_column(String(40), index=True)
    state: Mapped[str] = mapped_column(String(40), default="published")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    enriched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class Identifier(Base):
    __tablename__ = "vulnerability_identifiers"
    value: Mapped[str] = mapped_column(String(200), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20), index=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), index=True
    )


class Source(Base):
    __tablename__ = "sources"
    name: Mapped[str] = mapped_column(String(80), primary_key=True)
    checkpoint: Mapped[dict] = mapped_column(JSON, default=dict)
    last_attempt: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_success: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(30), default="never")
    error: Mapped[str | None] = mapped_column(Text)


class ApplicationSetting(Base):
    __tablename__ = "application_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, onupdate=now)


class SourceRecord(Base):
    __tablename__ = "source_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(ForeignKey("sources.name"))
    key: Mapped[str] = mapped_column(String(200))
    vulnerability_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id"), index=True
    )
    digest: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (UniqueConstraint("source", "key"),)


class Snapshot(Base):
    __tablename__ = "source_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    record_id: Mapped[int] = mapped_column(ForeignKey("source_records.id"), index=True)
    digest: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)


class Fact(Base):
    """Typed, source-owned facts: products, severity, attribution, remediation, KEV, EPSS.

    Current projection is normalized by vulnerability/source/kind/key. Source snapshots
    and changes preserve every prior value, including deletion. No source clobbers another.
    """

    __tablename__ = "vulnerability_facts"
    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), index=True
    )
    source: Mapped[str] = mapped_column(ForeignKey("sources.name"))
    kind: Mapped[str] = mapped_column(String(40), index=True)
    key: Mapped[str] = mapped_column(String(200))
    data: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("vulnerability_id", "source", "kind", "key"),)


class Change(Base):
    __tablename__ = "vulnerability_change_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), index=True
    )
    source: Mapped[str] = mapped_column(String(80))
    field: Mapped[str] = mapped_column(String(240))
    previous: Mapped[dict | None] = mapped_column(JSON)
    current: Mapped[dict | None] = mapped_column(JSON)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)


class ScoreHistory(Base):
    __tablename__ = "epss_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"), index=True
    )
    cve: Mapped[str] = mapped_column(String(40))
    date: Mapped[str] = mapped_column(String(10))
    probability: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)
    __table_args__ = (UniqueConstraint("cve", "date"),)


class Run(Base):
    __tablename__ = "collection_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    started: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    finished: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(30), default="running")
    processed: Mapped[int] = mapped_column(default=0)
    created: Mapped[int] = mapped_column(default=0)
    updated: Mapped[int] = mapped_column(default=0)
    failed: Mapped[int] = mapped_column(default=0)
    errors: Mapped[int] = mapped_column(default=0)
    rate_limits: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text)


class ReportRun(Base):
    __tablename__ = "report_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    started: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    checkpoint: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(30), default="running")
    baseline: Mapped[bool] = mapped_column(default=False)
    custom: Mapped[bool] = mapped_column(default=False)
    path: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)


class Metric(Base):
    __tablename__ = "daily_metrics"
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    data: Mapped[dict] = mapped_column(JSON)


class Lock(Base):
    __tablename__ = "job_locks"
    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    owner: Mapped[str] = mapped_column(String(80))
    acquired: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


Index("ix_fact_lookup", Fact.kind, Fact.vulnerability_id)
