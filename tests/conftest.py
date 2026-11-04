import os
import pytest
from app.database.models import Base
from app.database.session import connect
from app.config import Settings


@pytest.fixture
def db(tmp_path):
    # TEST_DATABASE_URL must designate an isolated disposable PostgreSQL database.
    url = os.environ.get("TEST_DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    engine, sessions = connect(url)
    Base.metadata.create_all(engine)
    settings = Settings(
        database_url=url,
        report_dir=tmp_path / "reports",
        request_interval=0,
        priority_config=__import__("pathlib").Path("config/priority.yml"),
    )
    yield engine, sessions, settings
    Base.metadata.drop_all(engine)
    engine.dispose()
