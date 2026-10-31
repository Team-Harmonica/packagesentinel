"""Acquisition failures (stdlib only).

Kept separate from contracts.py, which needs pydantic, so the zero-dependency
scanner path (archive.py / npm.py / pypi.py / app.detection.resolver) can
raise and catch these without importing pydantic. contracts.py re-exports them.
"""


class AcquisitionError(Exception):
    """Base class for failures that prevent package acquisition."""


class PackageNotFoundError(AcquisitionError):
    """The requested package does not exist in the selected registry."""


class VersionNotFoundError(AcquisitionError):
    """The package exists, but the exact requested version does not."""


class RegistryError(AcquisitionError):
    """A registry request failed or returned an unusable response."""


class ArchiveValidationError(AcquisitionError):
    """The downloaded archive failed validation."""


class ExtractionError(AcquisitionError):
    """The validated archive could not be safely extracted."""
