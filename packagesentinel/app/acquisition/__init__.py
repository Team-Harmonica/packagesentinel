"""Package acquisition: contracts, safe archive extraction, npm and PyPI fetchers.

Exports are loaded lazily (PEP 562) so that importing a stdlib-only submodule,
e.g. ``app.acquisition.archive`` from the zero-dependency scanner, does not
import pydantic via ``contracts``. ``from app.acquisition import X`` still works.
"""

_CONTRACTS = {"AcquiredPackage", "PackageAcquirer", "SkippedFile"}
_ERRORS = {
    "AcquisitionError",
    "ArchiveValidationError",
    "ExtractionError",
    "PackageNotFoundError",
    "RegistryError",
    "VersionNotFoundError",
}

__all__ = sorted(_CONTRACTS | _ERRORS)


def __getattr__(name: str):
    if name in _ERRORS:
        from app.acquisition import errors

        return getattr(errors, name)
    if name in _CONTRACTS:
        from app.acquisition import contracts

        return getattr(contracts, name)
    raise AttributeError(f"module 'app.acquisition' has no attribute {name!r}")
