"""Configuration settings for PackageSentinel backend."""

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application metadata
    app_name: str = "PackageSentinel Backend"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    # Default to sqlite+aiosqlite for zero-setup local dev/testing;
    # Can be configured to postgresql+psycopg://user:pass@host:5432/db for production
    database_url: str = Field(
        default="sqlite+aiosqlite:///./packagesentinel.db",
        description="Async database connection URL (PostgreSQL or SQLite)",
    )
    db_echo: bool = False

@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
