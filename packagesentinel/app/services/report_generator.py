"""Standardized JSON security report generator for PackageSentinel."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from app.core.compatibility import (
    analysis_stages_complete,
    calculate_stage_coverage,
)
from app.core.evidence import AggregatedEvidence
from app.schemas.finding import Finding
from app.schemas.package import PackageInfo
from app.schemas.report import (
    CompatibilityProfile,
    CorrelationResult,
    ScanReport,
)


class ReportGenerator:
    """Service producing standardized, consumer-ready scan reports."""

    def build_summary(
        self,
        package: PackageInfo,
        evidence: AggregatedEvidence,
        correlations: List[CorrelationResult],
        compatibility_profile: CompatibilityProfile,
        analysis_complete: bool,
    ) -> str:
        """Construct a summary without assigning a risk score or verdict."""
        pkg_label = f"{package.ecosystem}:{package.name}@{package.version}"
        count = evidence.unique_findings_count
        if not analysis_complete:
            return (
                f"Analysis of {pkg_label} is incomplete "
                f"({compatibility_profile.coverage}% stage coverage); "
                f"{count} unique finding(s) are currently recorded."
            )
        return (
            f"Analysis of {pkg_label} completed with {count} unique finding(s) "
            f"and {len(correlations)} correlated pattern(s)."
        )

    def generate_report(
        self,
        scan_id: UUID,
        package: PackageInfo,
        evidence: AggregatedEvidence,
        correlations: List[CorrelationResult],
        compatibility_profile: CompatibilityProfile,
        analyzer_execution_statuses: Dict[str, str],
        analyzer_errors: Optional[Dict[str, str]],
        created_at: datetime,
        completed_at: Optional[datetime] = None,
        custom_summary: Optional[str] = None,
    ) -> ScanReport:
        """Assemble all intelligence components into a validated ScanReport schema."""
        # Convert unique findings to standard Finding list for presentation
        presentation_findings: List[Finding] = []
        for df in evidence.unique_findings:
            presentation_findings.append(
                Finding(
                    rule_id=df.rule_id,
                    category=df.category,
                    severity=df.severity,
                    confidence=df.confidence,
                    file=df.file,
                    line=df.line,
                    evidence=df.evidence,
                    source=df.primary_source,
                    metadata={
                        "corroborating_sources": df.sources,
                        "corroboration_count": df.corroboration_count,
                    },
                )
            )

        compatibility_profile = compatibility_profile.model_copy(
            update={
                "coverage": calculate_stage_coverage(
                    compatibility_profile.stages,
                    compatibility_profile.applicable_stages,
                )
            }
        )
        analysis_complete = analysis_stages_complete(
            compatibility_profile.stages,
            compatibility_profile.applicable_stages,
        )
        summary = (
            custom_summary
            if custom_summary and analysis_complete
            else self.build_summary(
                package=package,
                evidence=evidence,
                correlations=correlations,
                compatibility_profile=compatibility_profile,
                analysis_complete=analysis_complete,
            )
        )

        return ScanReport(
            scan_id=scan_id,
            package=package,
            summary=summary,
            severity_counts=evidence.severity_counts,
            findings=presentation_findings,
            correlations=correlations,
            compatibility_profile=compatibility_profile,
            analyzer_execution_statuses=analyzer_execution_statuses,
            analyzer_errors=analyzer_errors or {},
            analysis_complete=analysis_complete,
            job_status="completed",
            created_at=created_at,
            completed_at=completed_at,
        )
