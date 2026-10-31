"""Tests for standardized JSON report generation."""

from datetime import datetime, timezone
from uuid import uuid4

from app.core.evidence import aggregate_evidence
from app.schemas.finding import Finding, Severity
from app.schemas.package import PackageInfo
from app.schemas.report import CompatibilityProfile, CorrelationResult
from app.services.report_generator import ReportGenerator


def test_standardized_report_generation():
    """Verify ReportGenerator compiles all intelligence attributes into schema."""
    gen = ReportGenerator()
    scan_id = uuid4()
    now = datetime.now(timezone.utc)

    pkg = PackageInfo(name="test-crypto", ecosystem="npm", version="1.2.3")
    evidence = aggregate_evidence([
        Finding(
            rule_id="NET-1",
            category="network_exfiltration",
            severity=Severity.CRITICAL,
            confidence=0.9,
            evidence="Outbound network POST",
            source="static_test",
        )
    ])

    correlations = [
        CorrelationResult(
            rule_id="CORR-TEST",
            category="compound_risk",
            severity=Severity.HIGH,
            description="Test compound risk",
            contributing_findings=[],
        )
    ]

    profile = CompatibilityProfile(
        stages={"static_analysis": "completed", "metadata_analysis": "completed"},
        coverage=50.0,
    )

    statuses = {"static_analysis": "completed", "metadata_analysis": "completed"}

    report = gen.generate_report(
        scan_id=scan_id,
        package=pkg,
        evidence=evidence,
        correlations=correlations,
        compatibility_profile=profile,
        analyzer_execution_statuses=statuses,
        analyzer_errors={},
        created_at=now,
        completed_at=now,
    )

    # Validate output schema
    assert report.scan_id == scan_id
    assert report.package.name == "test-crypto"
    assert report.package.ecosystem == "npm"
    assert report.package.version == "1.2.3"
    assert report.severity_counts["critical"] == 1
    assert len(report.findings) == 1
    assert len(report.correlations) == 1
    assert report.compatibility_profile.coverage == 50.0
    assert report.analysis_complete is True
    assert "completed" in report.summary
