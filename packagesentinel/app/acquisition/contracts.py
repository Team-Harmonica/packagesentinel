"""Shared types for package acquisition and its consumers.

An acquirer transfers ownership of its temporary directory to the returned
``AcquiredPackage``. The caller must call ``cleanup()`` after analysis, even
when analysis raises.
"""

from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.package import PackageRequest


# Defined in errors.py (stdlib only) so the zero-dependency scanner path can use
# them; re-exported here so existing imports keep working.
from app.acquisition.errors import (  # noqa: E402
    AcquisitionError,
    ArchiveValidationError,
    ExtractionError,
    PackageNotFoundError,
    RegistryError,
    VersionNotFoundError,
)


class SkippedFile(BaseModel):
    """A package file deliberately omitted during extraction."""

    model_config = ConfigDict(str_strip_whitespace=True)

    path: str = Field(..., min_length=1, description="Package-relative file path")
    reason: str = Field(..., min_length=1, description="Why the file was skipped")


class AcquiredPackage(BaseModel):
    """An acquired package ready for analysis, plus its owned temporary storage.

    ``temporary_directory`` must be the handle that owns ``extracted_dir``.
    Ownership transfers to the caller when this object is returned; the caller
    must invoke ``cleanup()`` after all analyzers finish.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        str_strip_whitespace=True,
    )

    package_name: str = Field(..., min_length=1, description="Canonical package name")
    ecosystem: Literal["npm", "pypi"]
    version: str = Field(..., min_length=1, description="Exact requested version")
    extracted_dir: Path = Field(..., description="Directory containing package contents")
    archive_sha256: str = Field(..., description="Lowercase SHA-256 digest of the archive")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Normalized registry metadata; registry-independent keys and values",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal acquisition or extraction warnings",
    )
    skipped_files: list[SkippedFile] = Field(
        default_factory=list,
        description="Files deliberately omitted during extraction",
    )
    temporary_directory: TemporaryDirectory = Field(
        ...,
        exclude=True,
        repr=False,
        description="Temporary-directory handle that owns extracted_dir",
    )

    @model_validator(mode="after")
    def validate_artifact(self) -> "AcquiredPackage":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.archive_sha256):
            raise ValueError("archive_sha256 must be a 64-character SHA-256 hex digest")
        self.archive_sha256 = self.archive_sha256.lower()

        root = Path(self.temporary_directory.name).resolve()
        extracted_dir = self.extracted_dir.resolve()
        if not extracted_dir.is_dir():
            raise ValueError("extracted_dir must point to an existing directory")
        if not extracted_dir.is_relative_to(root):
            raise ValueError("extracted_dir must be owned by temporary_directory")

        return self

    def cleanup(self) -> None:
        """Remove the owned temporary directory; safe to call more than once."""
        self.temporary_directory.cleanup()


@runtime_checkable
class PackageAcquirer(Protocol):
    """Async interface implemented by npm, PyPI, and test acquirers."""

    async def acquire(self, request: PackageRequest) -> AcquiredPackage:
        """Acquire the exact requested version or raise an ``AcquisitionError``."""
