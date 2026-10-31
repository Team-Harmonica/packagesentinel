"""Configuration settings for PackageSentinel backend."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "PackageSentinel Backend"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    database_url: str = Field(
        default="sqlite+aiosqlite:///./packagesentinel.db",
        description="Async SQLite database URL",
    )
    db_echo: bool = False

    @field_validator("database_url")
    @classmethod
    def require_sqlite_database(cls, value: str) -> str:
        """Reject database URLs for unsupported external database backends."""
        if not value.startswith("sqlite+aiosqlite://"):
            raise ValueError("database_url must use the sqlite+aiosqlite driver")
        return value


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
