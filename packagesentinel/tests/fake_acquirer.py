"""Network-free PackageAcquirer implementation for contract tests."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from app.acquisition.contracts import (
    AcquiredPackage,
    AcquisitionError,
)
from app.schemas.package import PackageRequest


class FakePackageAcquirer:
    """Create a small local package artifact without contacting a registry."""

    def __init__(self, error: AcquisitionError | None = None) -> None:
        self.error = error

    async def acquire(self, request: PackageRequest) -> AcquiredPackage:
        if self.error is not None:
            raise self.error

        temporary_directory = TemporaryDirectory(prefix="packagesentinel-test-")
        extracted_dir = Path(temporary_directory.name) / "package"
        extracted_dir.mkdir()
        (extracted_dir / "metadata.json").write_text(
            json.dumps({"name": request.name, "version": request.version}),
            encoding="utf-8",
        )
        (extracted_dir / "sample.txt").write_text(
            "test package contents\n",
            encoding="utf-8",
        )

        archive_bytes = f"{request.ecosystem.value}:{request.name}@{request.version}".encode()
        return AcquiredPackage(
            package_name=request.name,
            ecosystem=request.ecosystem.value,
            version=request.version,
            extracted_dir=extracted_dir,
            archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
            metadata={
                "name": request.name,
                "version": request.version,
                "registry": request.ecosystem.value,
            },
            temporary_directory=temporary_directory,
        )
