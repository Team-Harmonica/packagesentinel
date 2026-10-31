"""Tests for recording failures from individual analyzers."""

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.orchestrator import ScanOrchestrator
from app.database import repository
from app.detection.analyzers import AnalyzerResult, BaseAnalyzer
from app.schemas.package import Ecosystem, PackageRequest


class CrashingAnalyzer(BaseAnalyzer):
    name = "crashing_analyzer"

    async def analyze(self, package: PackageRequest, acquired_package=None) -> AnalyzerResult:
        assert acquired_package is not None
        assert acquired_package.extracted_dir.is_dir()
        self.temporary_directory = Path(acquired_package.temporary_directory.name)
        raise RuntimeError("analyzer unavailable")


@pytest.mark.asyncio
async def test_analyzer_exception_is_recorded_without_a_verdict(db_session: AsyncSession):
    package = await repository.get_or_create_package(db_session, "package", "npm")
    version = await repository.get_or_create_package_version(db_session, package.id, "1.0.0")
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()

    request = PackageRequest(ecosystem=Ecosystem.NPM, name="package", version="1.0.0")
    analyzer = CrashingAnalyzer()
    report = await ScanOrchestrator(analyzers=[analyzer]).execute_scan(
        db_session,
        scan.id,
        request,
    )

    assert report.analyzer_execution_statuses["static_analysis"] == "failed"
    assert report.analyzer_execution_statuses["acquisition"] == "completed"
    assert report.analysis_complete is False
    assert "analyzer unavailable" in report.analyzer_errors["static_analysis"]
    assert not analyzer.temporary_directory.exists()
    persisted_scan = await repository.get_scan_with_findings(db_session, scan.id)
    assert persisted_scan is not None
    assert persisted_scan.status == "completed"
