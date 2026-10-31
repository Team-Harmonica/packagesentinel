"""Tests for end-to-end scan orchestration without simulated detections."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.orchestrator import ScanOrchestrator
from app.database import repository
from app.schemas.package import Ecosystem, PackageRequest


@pytest.mark.asyncio
async def test_orchestrator_reports_unavailable_package_contents(db_session: AsyncSession):
    pkg = await repository.get_or_create_package(db_session, "clean-package", "npm")
    version = await repository.get_or_create_package_version(db_session, pkg.id, "1.0.0")
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()

    request = PackageRequest(
        ecosystem=Ecosystem.NPM,
        name="clean-package",
        version="1.0.0",
    )
    report = await ScanOrchestrator().execute_scan(db_session, scan.id, request)

    assert report.scan_id == scan.id
    assert report.analysis_complete is False
    assert report.compatibility_profile.coverage == 0.0
    assert report.compatibility_profile.stages["static_analysis"] == "not_available"
    assert "package contents" in report.analyzer_errors["static_analysis"].lower()
    assert report.findings == []
    assert "incomplete" in report.summary.lower()

    saved = await repository.get_scan_with_findings(db_session, scan.id)
    assert saved is not None
    assert saved.status == "completed"
    assert saved.summary == report.summary
    assert saved.findings == []
