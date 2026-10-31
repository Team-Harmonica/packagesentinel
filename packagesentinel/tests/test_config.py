"""Tests for backend runtime configuration."""

import sys

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_backend_import_does_not_load_object_storage_clients():
    import app.main  # noqa: F401

    client_modules = {"boto3", "botocore", "minio", "cloudflare"}
    assert client_modules.isdisjoint(sys.modules)


def test_settings_default_to_async_sqlite_without_external_credentials():
    settings = Settings(_env_file=None)

    assert settings.database_url == "sqlite+aiosqlite:///./packagesentinel.db"


def test_settings_reject_non_sqlite_database_urls():
    with pytest.raises(ValidationError, match="sqlite\\+aiosqlite"):
        Settings(_env_file=None, database_url="unsupported://localhost/db")


def test_settings_have_no_object_storage_configuration():
    configuration_fields = Settings.model_fields

    assert not any(
        term in field_name.lower()
        for field_name in configuration_fields
        for term in ("storage", "bucket", "s3", "minio", "r2")
    )
