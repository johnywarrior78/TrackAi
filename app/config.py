from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///aivi.db"
    report_dir: Path = Path("reports")
    log_dir: Path = Path("logs")
    schedule_hour: int = Field(7, ge=0, le=23)
    schedule_minute: int = Field(0, ge=0, le=59)
    http_timeout: float = Field(30, gt=0)
    http_retries: int = Field(4, ge=1, le=10)
    request_interval: float = Field(1, ge=0)
    github_token: str = ""
    anthropic_snapshots: str = "2026-05-22-1027,2026-08-26-1155"
    cve_repo_path: str = ""
    cache_dir: Path = Path(".cache")
    epss_bulk_threshold: int = Field(1000, ge=1)
    enrichment_limit: int = Field(500, ge=1)
    priority_config: Path = Path("config/priority.yml")
