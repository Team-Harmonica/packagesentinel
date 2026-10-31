"""Tests for end-to-end scan orchestration without simulated detections."""

import asyncio
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.acquisition.errors import RegistryError
from app.core.orchestrator import ScanOrchestrator
from app.database import repository
from app.schemas.package import Ecosystem, PackageRequest
from tests.fake_acquirer import FakePackageAcquirer


@pytest.mark.asyncio
async def test_orchestrator_acquires_and_analyzes_package_contents(db_session: AsyncSession):
    pkg = await repository.get_or_create_package(db_session, "clean-package", "npm")
    version = await repository.get_or_create_package_version(db_session, pkg.id, "1.0.0")
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()

    request = PackageRequest(
        ecosystem=Ecosystem.NPM,
        name="clean-package",
        version="1.0.0",
    )
    acquirer = FakePackageAcquirer(
        sample_files={"index.js": 'eval(atob("Y29uc29sZS5sb2coMSk="))'}
    )

    class StatusCheckingAcquirer:
        async def acquire(self, package_request):
            current = await repository.get_scan(db_session, scan.id)
            assert current is not None
            assert current.status == "fetching"
            return await acquirer.acquire(package_request)

    report = await ScanOrchestrator(package_acquirer=StatusCheckingAcquirer()).execute_scan(
        db_session,
        scan.id,
        request,
    )

    assert acquirer.last_request == request
    assert report.scan_id == scan.id
    assert report.analysis_complete is False
    assert report.job_status == "completed"
    assert report.compatibility_profile.coverage == 40.0
    assert report.compatibility_profile.stages["static_analysis"] == "completed"
    assert report.compatibility_profile.stages["metadata_analysis"] == "unavailable"
    assert report.compatibility_profile.stages["typosquatting_analysis"] == "completed"
    assert report.compatibility_profile.stages["behavioral_analysis"] == "unavailable"
    assert report.compatibility_profile.stages["dependency_analysis"] == "unavailable"
    assert report.analyzer_execution_statuses["acquisition"] == "completed"
    assert report.package.archive_hash == acquirer.last_artifact.archive_sha256
    assert report.findings
    assert "incomplete" in report.summary.lower()
    assert not Path(acquirer.last_artifact.temporary_directory.name).exists()

    saved = await repository.get_scan_with_findings(db_session, scan.id)
    assert saved is not None
    assert saved.status == "completed"
    assert saved.summary == report.summary
    assert saved.package_version.archive_hash == acquirer.last_artifact.archive_sha256
    assert saved.findings


@pytest.mark.asyncio
async def test_acquisition_failure_is_reported_without_claiming_safe_analysis(
    db_session: AsyncSession,
):
    package = await repository.get_or_create_package(db_session, "missing-pkg", "npm")
    version = await repository.get_or_create_package_version(
        db_session,
        package.id,
        "1.0.0",
    )
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()
    request = PackageRequest(ecosystem=Ecosystem.NPM, name="missing-pkg", version="1.0.0")

    report = await ScanOrchestrator(
        package_acquirer=FakePackageAcquirer(error=RegistryError("registry unavailable"))
    ).execute_scan(db_session, scan.id, request)

    assert report.analysis_complete is False
    assert report.analyzer_execution_statuses["acquisition"] == "failed"
    assert "registry unavailable" in report.analyzer_errors["acquisition"]
    assert report.analyzer_execution_statuses["static_analysis"] == "skipped"
    saved = await repository.get_scan_with_findings(db_session, scan.id)
    assert saved is not None
    assert saved.status == "completed"
    assert saved.analyzer_statuses_json["acquisition"] == "failed"


@pytest.mark.asyncio
async def test_acquisition_timeout_is_recorded_and_analysis_is_incomplete(
    db_session: AsyncSession,
):
    class HangingAcquirer:
        async def acquire(self, package):
            await asyncio.Event().wait()

    package = await repository.get_or_create_package(db_session, "slow-pkg", "npm")
    version = await repository.get_or_create_package_version(
        db_session,
        package.id,
        "1.0.0",
    )
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()
    request = PackageRequest(ecosystem=Ecosystem.NPM, name="slow-pkg", version="1.0.0")

    report = await ScanOrchestrator(
        package_acquirer=HangingAcquirer(),
        acquisition_timeout_seconds=0.01,
    ).execute_scan(db_session, scan.id, request)

    assert report.analysis_complete is False
    assert report.analyzer_execution_statuses["acquisition"] == "failed"
    assert "timed out" in report.analyzer_errors["acquisition"]
    assert report.analyzer_execution_statuses["static_analysis"] == "skipped"


@pytest.mark.asyncio
async def test_orchestrator_persists_typosquat_finding_during_acquisition(
    db_session: AsyncSession,
):
    pkg = await repository.get_or_create_package(db_session, "reqeusts", "pypi")
    version = await repository.get_or_create_package_version(db_session, pkg.id, "1.0.0")
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()

    request = PackageRequest(
        ecosystem=Ecosystem.PYPI,
        name="reqeusts",
        version="1.0.0",
    )
    report = await ScanOrchestrator().execute_scan(db_session, scan.id, request)

    assert report.analysis_complete is False
    assert report.job_status == "completed"
    assert report.compatibility_profile.stages["metadata_analysis"] == "unavailable"
    assert report.compatibility_profile.stages["typosquatting_analysis"] == "completed"
    assert report.compatibility_profile.coverage == 40.0
    assert len(report.findings) == 1
    assert report.findings[0].category == "typosquatting"
    assert "requests" in report.findings[0].evidence

    saved = await repository.get_scan_with_findings(db_session, scan.id)
    assert saved is not None
    assert len(saved.findings) == 1
    assert saved.findings[0].category == "typosquatting"
