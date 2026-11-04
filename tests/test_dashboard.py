"""Render every page with an isolated empty database; no external network."""

from streamlit.testing.v1 import AppTest
from pathlib import Path


def test_all_dashboard_pages(db, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", db[2].database_url)
    monkeypatch.setenv("REPORT_DIR", str(db[2].report_dir))
    at = AppTest.from_file(
        Path("app/dashboard/main.py").resolve(), default_timeout=30
    ).run()
    assert not at.exception
    for page in [
        "Vulnerability Explorer",
        "Vulnerability Details",
        "AI Research Landscape",
        "Historical Analytics",
        "Source Health",
        "Reporting",
    ]:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, page
