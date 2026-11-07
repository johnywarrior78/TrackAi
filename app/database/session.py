from contextlib import contextmanager
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker


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

    Native SQLite evaluation uses OS file locks, released automatically on crash.
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
        import fcntl
        import os
        from pathlib import Path
        import tempfile

        database = engine.url.database
        if database and database != ":memory:":
            path = Path(database).resolve()
            folder = path.parent / (path.name + ".locks")
        else:
            folder = (
                Path(tempfile.gettempdir()) / f"aivi-locks-{os.getpid()}-{id(engine)}"
            )
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        lockfile = folder / hashlib.sha256(name.encode()).hexdigest()
        descriptor = os.open(lockfile, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, "a+") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(f"Job already running: {name}") from exc
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
