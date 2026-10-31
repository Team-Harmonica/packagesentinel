"""Tests for the shared package acquisition contract."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from pydantic import ValidationError

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
from app.schemas.package import Ecosystem, PackageRequest
from tests.fake_acquirer import FakePackageAcquirer


def make_artifact(
    temporary_directory: TemporaryDirectory,
    *,
    ecosystem: str = "npm",
    archive_sha256: str | None = None,
    metadata: dict[str, object] | None = None,
    warnings: list[str] | None = None,
    skipped_files: list[SkippedFile] | None = None,
) -> AcquiredPackage:
    extracted_dir = Path(temporary_directory.name) / "package"
    extracted_dir.mkdir(exist_ok=True)
    return AcquiredPackage(
        package_name="sample-package",
        ecosystem=ecosystem,
        version="1.2.3",
        extracted_dir=extracted_dir,
        archive_sha256=(
            hashlib.sha256(b"archive").hexdigest()
            if archive_sha256 is None
            else archive_sha256
        ),
        metadata=metadata or {"name": "sample-package", "version": "1.2.3"},
        warnings=warnings or [],
        skipped_files=skipped_files or [],
        temporary_directory=temporary_directory,
    )


@pytest.mark.parametrize("ecosystem", ["npm", "pypi"])
def test_artifact_contains_required_fields_and_types(ecosystem: str):
    temporary_directory = TemporaryDirectory()
    try:
        artifact = make_artifact(temporary_directory, ecosystem=ecosystem)

        assert artifact.package_name == "sample-package"
        assert artifact.ecosystem == ecosystem
        assert artifact.version == "1.2.3"
        assert isinstance(artifact.extracted_dir, Path)
        assert artifact.extracted_dir.is_dir()
        assert len(artifact.archive_sha256) == 64
        assert isinstance(artifact.metadata, dict)
        assert artifact.warnings == []
        assert artifact.skipped_files == []
        assert artifact.temporary_directory is temporary_directory
    finally:
        temporary_directory.cleanup()


def test_ecosystem_is_restricted_and_hash_is_normalized():
    temporary_directory = TemporaryDirectory()
    try:
        artifact = make_artifact(
            temporary_directory,
            ecosystem="pypi",
            archive_sha256="A" * 64,
        )
        assert artifact.archive_sha256 == "a" * 64

        with pytest.raises(ValidationError):
            make_artifact(temporary_directory, ecosystem="rubygems")
    finally:
        temporary_directory.cleanup()


@pytest.mark.parametrize("digest", ["", "a" * 63, "g" * 64, "a" * 65])
def test_invalid_sha256_representation_is_rejected(digest: str):
    temporary_directory = TemporaryDirectory()
    try:
        with pytest.raises(ValidationError, match="SHA-256"):
            make_artifact(temporary_directory, archive_sha256=digest)
    finally:
        temporary_directory.cleanup()


def test_metadata_warnings_and_skipped_files_are_structured():
    temporary_directory = TemporaryDirectory()
    try:
        artifact = make_artifact(
            temporary_directory,
            metadata={"description": "sample", "downloads": 12},
            warnings=["Some registry metadata was unavailable"],
            skipped_files=[
                SkippedFile(path="large.bin", reason="exceeded extraction size limit")
            ],
        )

        assert artifact.metadata["downloads"] == 12
        assert artifact.warnings == ["Some registry metadata was unavailable"]
        assert artifact.skipped_files == [
            SkippedFile(path="large.bin", reason="exceeded extraction size limit")
        ]
    finally:
        temporary_directory.cleanup()


def test_skipped_file_requires_path_and_reason():
    with pytest.raises(ValidationError):
        SkippedFile(path="", reason="not extracted")
    with pytest.raises(ValidationError):
        SkippedFile(path="large.bin", reason="  ")


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", list(Ecosystem))
async def test_fake_acquirer_satisfies_protocol_and_returns_artifact(ecosystem: Ecosystem):
    request = PackageRequest(
        ecosystem=ecosystem,
        name="  sample-package ",
        version=" 1.2.3 ",
    )
    acquirer = FakePackageAcquirer()
    typed_acquirer: PackageAcquirer = acquirer
    assert isinstance(acquirer, PackageAcquirer)

    artifact = await typed_acquirer.acquire(request)
    try:
        assert artifact.package_name == request.name
        assert artifact.ecosystem == request.ecosystem.value
        assert artifact.version == request.version
        assert artifact.extracted_dir.joinpath("metadata.json").is_file()
        assert artifact.extracted_dir.joinpath("sample.txt").is_file()
        assert len(artifact.archive_sha256) == 64
        assert artifact.metadata["registry"] == ecosystem.value
    finally:
        artifact.cleanup()


@pytest.mark.asyncio
async def test_fake_acquirer_propagates_explicit_acquisition_failure():
    error = VersionNotFoundError("requested version is unavailable")
    with pytest.raises(VersionNotFoundError, match="requested version"):
        await FakePackageAcquirer(error=error).acquire(
            PackageRequest(ecosystem="pypi", name="sample-package", version="9.9.9")
        )


@pytest.mark.parametrize(
    "error_type",
    [
        PackageNotFoundError,
        VersionNotFoundError,
        RegistryError,
        ArchiveValidationError,
        ExtractionError,
    ],
)
def test_acquisition_failures_share_a_common_base(error_type: type[AcquisitionError]):
    error = error_type("failure")
    assert isinstance(error, AcquisitionError)
    assert str(error) == "failure"


def test_cleanup_removes_temporary_contents_and_is_idempotent():
    temporary_directory = TemporaryDirectory()
    artifact = make_artifact(temporary_directory)
    root = Path(temporary_directory.name)
    assert root.exists()

    artifact.cleanup()
    artifact.cleanup()

    assert not root.exists()


def test_extracted_directory_must_be_owned_by_cleanup_handle():
    owner = TemporaryDirectory()
    other = TemporaryDirectory()
    try:
        unrelated_dir = Path(other.name)
        with pytest.raises(ValidationError, match="owned by temporary_directory"):
            AcquiredPackage(
                package_name="sample-package",
                ecosystem="npm",
                version="1.2.3",
                extracted_dir=unrelated_dir,
                archive_sha256=hashlib.sha256(b"archive").hexdigest(),
                temporary_directory=owner,
            )
    finally:
        owner.cleanup()
        other.cleanup()


def test_existing_package_request_is_used_without_schema_changes():
    request = PackageRequest(ecosystem="npm", name="  lodash ", version=" 4.17.21 ")
    assert request.name == "lodash"
    assert request.version == "4.17.21"
    assert request.ecosystem is Ecosystem.NPM
