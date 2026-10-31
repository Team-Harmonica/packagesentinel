"""Scan report schemas and structured intelligence findings."""

from datetime import datetime
from typing import Dict, List, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field, field_validator
from app.schemas.finding import Finding, Severity
from app.schemas.package import PackageInfo

STANDARD_ANALYSIS_STAGES = [
    "static_analysis",
    "metadata_analysis",
    "typosquatting_analysis",
    "behavioral_analysis",
    "dependency_analysis",
]


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
        description="Execution status of each stage (completed, failed, skipped, unavailable)",
    )
    applicable_stages: List[str] = Field(
        default_factory=lambda: list(STANDARD_ANALYSIS_STAGES),
        description="Stages included in the coverage and analysis-completion calculation",
    )
    coverage: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated coverage percentage based on applicable stages",
    )

    @field_validator("stages", mode="before")
    @classmethod
    def normalize_legacy_stage_statuses(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not isinstance(value, dict):
            return value
        stages = {
            stage: "unavailable"
            for stage in STANDARD_ANALYSIS_STAGES
        }
        stages.update({
            stage: ("unavailable" if status == "not_available" else status)
            for stage, status in value.items()
        })
        return stages


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
    detection_flags: Dict[str, bool] = Field(
        default_factory=dict,
        description="Frontend-friendly positive detection flags for metadata and typosquatting",
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
    job_status: Literal["completed"] = Field(
        default="completed",
        description="Lifecycle status of the scan job; distinct from analysis completeness",
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when scan was initiated",
    )
    completed_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when scan completed or terminated",
    )

    @field_validator("analyzer_execution_statuses", mode="before")
    @classmethod
    def normalize_legacy_analyzer_statuses(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not isinstance(value, dict):
            return value
        return {
            stage: ("unavailable" if status == "not_available" else status)
            for stage, status in value.items()
        }
