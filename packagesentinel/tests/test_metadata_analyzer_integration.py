import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.acquisition.contracts import PackageAcquirer
from app.core.orchestrator import ScanOrchestrator
from app.database import repository
from app.detection.analyzers import (
    PackageContentAnalyzer,
    PackageMetadataAnalyzer,
    PackageTyposquattingAnalyzer,
)
from app.schemas.finding import Finding, Severity
from app.schemas.package import Ecosystem, PackageRequest
from tests.fake_acquirer import FakePackageAcquirer


@pytest.mark.asyncio
async def test_metadata_findings_flow_through_scan_persistence_and_report(
    db_session: AsyncSession,
):
    observed_metadata = {}

    def detect_metadata(metadata):
        observed_metadata.update(metadata)
        return [
            Finding(
                rule_id="META-001",
                category="suspicious_metadata",
                severity=Severity.HIGH,
                confidence=0.93,
                evidence="Package metadata points to an untrusted repository.",
                source="metadata_detector",
            )
        ]

    package = await repository.get_or_create_package(
        db_session,
        "metadata-risk-package",
        "npm",
    )
    version = await repository.get_or_create_package_version(
        db_session,
        package.id,
        "1.0.0",
    )
    scan = await repository.create_scan(db_session, version.id)
    await db_session.commit()
    request = PackageRequest(
        ecosystem=Ecosystem.NPM,
        name="metadata-risk-package",
        version="1.0.0",
    )
    acquirer: PackageAcquirer = FakePackageAcquirer()
    orchestrator = ScanOrchestrator(
        analyzers=[
            PackageMetadataAnalyzer(detector=detect_metadata),
            PackageTyposquattingAnalyzer(),
            PackageContentAnalyzer(),
        ],
        package_acquirer=acquirer,
    )

    report = await orchestrator.execute_scan(db_session, scan.id, request)

    assert observed_metadata["name"] == request.name
    assert observed_metadata["ecosystem"] == request.ecosystem.value
    assert observed_metadata["version"] == request.version
    assert report.analyzer_execution_statuses["metadata_analysis"] == "completed"
    assert report.compatibility_profile.stages["metadata_analysis"] == "completed"
    assert report.compatibility_profile.coverage == 60.0
    assert report.detection_flags == {
        "metadata": True,
        "typosquatting": False,
    }
    assert any(
        finding.rule_id == "META-001"
        and finding.category == "suspicious_metadata"
        and finding.confidence == 0.93
        and finding.source == "metadata_analysis"
        for finding in report.findings
    )

    persisted_scan = await repository.get_scan_with_findings(db_session, scan.id)
    assert persisted_scan is not None
    assert any(finding.rule_id == "META-001" for finding in persisted_scan.findings)
    assert persisted_scan.analyzer_statuses_json["metadata_analysis"] == "completed"
