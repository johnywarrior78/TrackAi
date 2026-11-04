from contextlib import contextmanager
from uuid import uuid4
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from app.database.models import Lock


def connect(url):
    engine = create_engine(url, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def pragma(dbapi, _):
            dbapi.execute("PRAGMA foreign_keys=ON")
            if engine.url.database and engine.url.database != ":memory:":
                from pathlib import Path

                Path(engine.url.database).chmod(0o600)

    return engine, sessionmaker(engine, expire_on_commit=False)


@contextmanager
def job_lock(engine, sessions, name):
    """Connection-scoped PostgreSQL lock auto-releases after process death.

    SQLite evaluation lock fails closed; remove only after confirming worker died.
    """
    import hashlib

    key = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big", signed=True)
    if engine.dialect.name == "postgresql":
        with engine.connect() as conn:
            if not conn.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}):
                raise RuntimeError(f"Job already running: {name}")
            try:
                yield
            finally:
                conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
    else:
        owner = str(uuid4())
        with sessions.begin() as session:
            session.add(Lock(name=name, owner=owner))
            try:
                session.flush()
            except IntegrityError as exc:
                raise RuntimeError(f"Job already running: {name}") from exc
        try:
            yield
        finally:
            with sessions.begin() as session:
                obj = session.get(Lock, name)
                if obj and obj.owner == owner:
                    session.delete(obj)
