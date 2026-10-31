"""Shared package acquisition contracts."""

from app.acquisition.contracts import (
    AcquiredPackage,
    AcquisitionError,
    ArchiveValidationError,
    ExtractionError,
    PackageAcquirer,
    PackageNotFoundError,
    RegistryError,
    SkippedFile,
    VersionNotFoundError,
)

__all__ = [
    "AcquiredPackage",
    "AcquisitionError",
    "ArchiveValidationError",
    "ExtractionError",
    "PackageAcquirer",
    "PackageNotFoundError",
    "RegistryError",
    "SkippedFile",
    "VersionNotFoundError",
]
