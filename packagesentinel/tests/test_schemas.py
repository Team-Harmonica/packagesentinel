"""Tests for Pydantic schema validation across all shared data contracts."""

import pytest
from pydantic import ValidationError
from uuid import uuid4

from app.schemas.finding import Finding, Severity
from app.schemas.package import Ecosystem, PackageInfo, PackageRequest
from app.schemas.scan import ScanResponse, ScanStatus
from app.schemas.report import (
    CompatibilityProfile,
    CorrelationResult,
    ScanReport,
)
from datetime import datetime, timezone


def test_package_request_valid():
    """Verify valid PackageRequest creation and whitespace trimming."""
    req = PackageRequest(
        ecosystem=Ecosystem.NPM,
        name="  lodash  ",
        version=" 4.17.21 ",
    )
    assert req.name == "lodash"
    assert req.version == "4.17.21"
    assert req.ecosystem == Ecosystem.NPM


def test_package_request_invalid_ecosystem():
    """Verify rejection of unsupported ecosystems."""
    with pytest.raises(ValidationError):
        PackageRequest(
            ecosystem="rubygems",  # type: ignore
            name="rails",
            version="7.0.0",
        )


def test_package_request_empty_fields():
    """Verify validation fails on empty strings or only whitespace."""
    with pytest.raises(ValidationError):
        PackageRequest(ecosystem=Ecosystem.PYPI, name="", version="1.0.0")

    with pytest.raises(ValidationError):
        PackageRequest(ecosystem=Ecosystem.PYPI, name="requests", version="   ")


def test_finding_valid():
    """Verify valid Finding model construction."""
    finding = Finding(
        rule_id="CRED-001",
        category="credential_access",
        severity=Severity.HIGH,
        confidence=0.9,
        file="auth.py",
        line=42,
        evidence="AWS credentials accessed",
        source="static_test",
        metadata={"detail": "T1552"},
    )
    assert finding.rule_id == "CRED-001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9


def test_finding_confidence_boundaries():
    """Verify confidence must be between 0.0 and 1.0."""
    with pytest.raises(ValidationError):
        Finding(
            rule_id="RULE-1",
            category="test",
            severity=Severity.LOW,
            confidence=1.5,  # > 1.0
            evidence="test",
            source="test",
        )

    with pytest.raises(ValidationError):
        Finding(
            rule_id="RULE-1",
            category="test",
            severity=Severity.LOW,
            confidence=-0.1,  # < 0.0
            evidence="test",
            source="test",
        )


def test_scan_response_contract():
    """Verify ScanResponse fields match specification."""
    scan_id = uuid4()
    resp = ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        message="Scan queued successfully",
    )
    assert resp.scan_id == scan_id
    assert resp.status == ScanStatus.QUEUED
    assert "queued" in resp.message.lower()


def test_scan_report_contract():
    """Verify ScanReport adheres to required fields."""
    scan_id = uuid4()
    now = datetime.now(timezone.utc)
    report = ScanReport(
        scan_id=scan_id,
        package=PackageInfo(name="test-pkg", ecosystem="npm", version="1.0.0"),
        summary="Analysis is incomplete.",
        severity_counts={"low": 1, "medium": 0, "high": 0, "critical": 0},
        findings=[],
        correlations=[],
        compatibility_profile=CompatibilityProfile(
            stages={"static_analysis": "not_available"},
            coverage=0.0,
        ),
        analyzer_execution_statuses={"static_analysis": "not_available"},
        analysis_complete=False,
        created_at=now,
        completed_at=now,
    )
    assert report.scan_id == scan_id
    assert report.analysis_complete is False
    assert report.compatibility_profile.coverage == 0.0
