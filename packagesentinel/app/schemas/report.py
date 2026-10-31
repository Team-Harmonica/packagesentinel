"""Scan report schemas and structured intelligence findings."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field
from app.schemas.finding import Finding, Severity
from app.schemas.package import PackageInfo


class CorrelationResult(BaseModel):
    """Correlated security threat pattern identified across multiple findings."""

    rule_id: str = Field(
        ...,
        description="Correlation rule identifier (e.g., 'CORR-CRED-EXFIL')",
    )
    category: str = Field(
        ...,
        description="Category classification for the correlated behavior",
    )
    severity: Severity = Field(
        ...,
        description="Severity level of the correlated behavior",
    )
    description: str = Field(
        ...,
        description="Explainable description of the compound behavior detected",
    )
    contributing_findings: List[Finding] = Field(
        default_factory=list,
        description="Underlying findings that triggered this correlation",
    )


class CompatibilityProfile(BaseModel):
    """Profile describing which analysis stages were executed and coverage achieved."""

    stages: Dict[str, str] = Field(
        default_factory=dict,
        description="Execution status of each analysis stage (completed, failed, not_available, skipped)",
    )
    coverage: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated coverage percentage based on applicable stages",
    )


class ScanReport(BaseModel):
    """Comprehensive security intelligence report for a scanned package."""

    scan_id: UUID = Field(
        ...,
        description="Scan task UUID",
    )
    package: PackageInfo = Field(
        ...,
        description="Target package metadata (name, ecosystem, version, archive_hash)",
    )
    summary: str = Field(
        ...,
        description="Summary of detections and analysis coverage",
    )
    severity_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of unique findings grouped by severity (low, medium, high, critical)",
    )
    findings: List[Finding] = Field(
        default_factory=list,
        description="List of all detected individual findings",
    )
    correlations: List[CorrelationResult] = Field(
        default_factory=list,
        description="Correlated multi-stage security behaviors detected",
    )
    compatibility_profile: CompatibilityProfile = Field(
        ...,
        description="Profile detailing stage execution and test coverage",
    )
    analyzer_execution_statuses: Dict[str, str] = Field(
        default_factory=dict,
        description="Status of each analyzer invoked during the scan",
    )
    analyzer_errors: Dict[str, str] = Field(
        default_factory=dict,
        description="Error or availability details for analyzers that did not complete",
    )
    analysis_complete: bool = Field(
        ...,
        description="Indicates whether all applicable analysis stages finished without blocking errors",
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when scan was initiated",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when scan completed or terminated",
    )
