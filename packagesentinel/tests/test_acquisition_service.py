import pytest

from app.acquisition.service import RegistryPackageAcquirer
from app.schemas.package import Ecosystem, PackageRequest
from tests.fake_acquirer import FakePackageAcquirer


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", list(Ecosystem))
async def test_registry_acquirer_routes_request_to_matching_backend(ecosystem):
    npm = FakePackageAcquirer()
    pypi = FakePackageAcquirer()
    request = PackageRequest(
        ecosystem=ecosystem,
        name="sample-package",
        version="1.2.3",
    )
    registry_acquirer = RegistryPackageAcquirer(npm, pypi)

    result = await registry_acquirer.acquire(request)

    assert result.package_name == request.name
    assert (npm.last_request is request) is (ecosystem is Ecosystem.NPM)
    assert (pypi.last_request is request) is (ecosystem is Ecosystem.PYPI)
    result.cleanup()
