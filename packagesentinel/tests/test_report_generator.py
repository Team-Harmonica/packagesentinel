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
        applicable_stages=["static_analysis", "metadata_analysis"],
        coverage=100.0,
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
    assert report.compatibility_profile.coverage == 100.0
    assert report.analysis_complete is True
    assert report.job_status == "completed"
    assert "completed" in report.summary


def test_report_uses_profile_coverage_and_marks_unavailable_analysis_incomplete():
    package = PackageInfo(name="test-package", ecosystem="npm", version="1.0.0")
    profile = CompatibilityProfile(
        stages={
            "static_analysis": "completed",
            "metadata_analysis": "unavailable",
        },
        applicable_stages=["static_analysis", "metadata_analysis"],
        coverage=100.0,
    )

    report = ReportGenerator().generate_report(
        scan_id=uuid4(),
        package=package,
        evidence=aggregate_evidence([]),
        correlations=[],
        compatibility_profile=profile,
        analyzer_execution_statuses={
            "static_analysis": "completed",
            "metadata_analysis": "unavailable",
            "acquisition": "completed",
        },
        analyzer_errors={"metadata_analysis": "Metadata analyzer is not implemented."},
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        custom_summary="Analysis completed with no findings.",
    )

    assert report.job_status == "completed"
    assert report.analysis_complete is False
    assert report.compatibility_profile.coverage == 50.0
    assert report.compatibility_profile.stages["metadata_analysis"] == "unavailable"
    assert "incomplete" in report.summary.lower()
    assert "no findings" not in report.summary.lower()
    assert report.analyzer_errors["metadata_analysis"]
