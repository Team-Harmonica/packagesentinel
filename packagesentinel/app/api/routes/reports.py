from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.evidence import aggregate_evidence
from app.database import repository
from app.database.connection import get_db_session
from app.schemas.finding import Finding, Severity
from app.schemas.package import PackageInfo
from app.schemas.report import CompatibilityProfile, CorrelationResult, ScanReport
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/scans", tags=["Reports"])


@router.get(
    "/{scan_id}/report",
    response_model=ScanReport,
    summary="Get completed security scan report",
    description="Returns findings, correlations, and analysis coverage for a completed scan.",
)
async def get_scan_report(
    scan_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> ScanReport:
    """Retrieve the full report for a completed scan."""
    scan = await repository.get_scan_with_findings(session, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )

    if scan.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Scan '{scan_id}' failed during analysis. Full report is unavailable.",
        )

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Scan '{scan_id}' is still in progress (current status: '{scan.status}'). "
                "Please retry after analysis finishes."
            ),
        )

    package_version = scan.package_version
    package = package_version.package
    package_info = PackageInfo(
        name=package.name,
        ecosystem=package.ecosystem,
        version=package_version.version,
        archive_hash=package_version.archive_hash,
    )
    findings = [
        Finding(
            rule_id=record.rule_id,
            category=record.category,
            severity=Severity(record.severity),
            confidence=record.confidence,
            file=record.file,
            line=record.line,
            evidence=record.evidence,
            source=record.source,
            metadata=record.metadata_json,
        )
        for record in scan.findings
    ]
    evidence = aggregate_evidence(findings)
    correlations = [
        CorrelationResult.model_validate(item)
        for item in (scan.correlations_json or [])
    ]
    compatibility_profile = CompatibilityProfile.model_validate(
        scan.compatibility_profile_json or {"stages": {}, "coverage": 0.0}
    )
    return ReportGenerator().generate_report(
        scan_id=scan.id,
        package=package_info,
        evidence=evidence,
        correlations=correlations,
        compatibility_profile=compatibility_profile,
        analyzer_execution_statuses=scan.analyzer_statuses_json or {},
        analyzer_errors=scan.analyzer_errors_json or {},
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        custom_summary=scan.summary,
    )
