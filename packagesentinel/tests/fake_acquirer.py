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

    def __init__(
        self,
        error: AcquisitionError | None = None,
        sample_files: dict[str, str] | None = None,
    ) -> None:
        self.error = error
        self.sample_files = sample_files or {}
        self.last_artifact: AcquiredPackage | None = None
        self.last_request: PackageRequest | None = None

    async def acquire(self, request: PackageRequest) -> AcquiredPackage:
        self.last_request = request
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
        for relative_path, content in self.sample_files.items():
            path = extracted_dir / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        archive_bytes = f"{request.ecosystem.value}:{request.name}@{request.version}".encode()
        artifact = AcquiredPackage(
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
        self.last_artifact = artifact
        return artifact
