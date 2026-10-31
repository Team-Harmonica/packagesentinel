"""Package schemas and request definitions."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class Ecosystem(str, Enum):
    """Supported package ecosystems."""
    NPM = "npm"
    PYPI = "pypi"


class PackageRequest(BaseModel):
    """Request payload for initiating a package security scan."""

    ecosystem: Ecosystem = Field(
        ...,
        description="Target package repository ecosystem (npm or pypi)",
        examples=["npm", "pypi"],
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Package name (e.g., 'express' or 'requests')",
        examples=["express"],
    )
    version: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Package semver version string",
        examples=["1.0.0"],
    )

    @field_validator("name", "version", mode="before")
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        """Strip surrounding whitespace and ensure non-empty strings."""
        if isinstance(value, str):
            value = value.strip()
            if not value:
                raise ValueError("Field cannot be empty or only whitespace")
        return value


class PackageInfo(BaseModel):
    """Package identity and version details."""

    name: str
    ecosystem: str
    version: str
    archive_hash: Optional[str] = None

