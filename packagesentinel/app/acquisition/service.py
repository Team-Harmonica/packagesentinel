"""Select the registry-specific package acquirer for a scan request."""

from app.acquisition.contracts import AcquiredPackage, PackageAcquirer
from app.schemas.package import PackageRequest


class RegistryPackageAcquirer:
    """Dispatch npm and PyPI requests through their shared acquisition contract."""

    def __init__(
        self,
        npm_acquirer: PackageAcquirer | None = None,
        pypi_acquirer: PackageAcquirer | None = None,
    ) -> None:
        if npm_acquirer is None:
            from app.acquisition.npm import NpmAcquirer

            npm_acquirer = NpmAcquirer()
        if pypi_acquirer is None:
            from app.acquisition.pypi import PyPIAcquirer

            pypi_acquirer = PyPIAcquirer()
        self._acquirers = {
            "npm": npm_acquirer,
            "pypi": pypi_acquirer,
        }

    async def acquire(self, request: PackageRequest) -> AcquiredPackage:
        """Acquire the request from its matching ecosystem registry."""
        acquirer = self._acquirers.get(request.ecosystem.value)
        if acquirer is None:
            raise ValueError(f"unsupported package ecosystem: {request.ecosystem.value}")
        return await acquirer.acquire(request)


def get_default_package_acquirer() -> PackageAcquirer:
    """Create the production acquirer used by scan workers."""
    return RegistryPackageAcquirer()
