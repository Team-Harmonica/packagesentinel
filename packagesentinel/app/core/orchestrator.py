"""Asynchronous scan orchestration, evidence aggregation, and report persistence."""

import asyncio
from datetime import datetime, timezone
import logging
import re
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.acquisition.contracts import AcquisitionError, AcquiredPackage, PackageAcquirer
from app.acquisition.service import get_default_package_acquirer
from app.core.compatibility import CompatibilityProfileGenerator
from app.core.correlation import CorrelationEngine
from app.core.evidence import aggregate_evidence
from app.database import repository
from app.detection.analyzers import (
    AnalyzerResult,
    AnalyzerStatus,
    BaseAnalyzer,
    PackageContentAnalyzer,
    PackageIdentityAnalyzer,
)
from app.schemas.finding import Finding
from app.schemas.package import PackageInfo, PackageRequest
from app.schemas.report import ScanReport
from app.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)
DEFAULT_ACQUISITION_TIMEOUT_SECONDS = 120


def _package_name_key(name: str, ecosystem: str) -> str:
    key = name.casefold()
    if ecosystem == "pypi":
        key = re.sub(r"[-_.]+", "-", key)
    return key


class ScanOrchestrator:
    """Run configured analyzers and persist their findings and report metadata."""

    def __init__(
        self,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        profile_generator: Optional[CompatibilityProfileGenerator] = None,
        report_generator: Optional[ReportGenerator] = None,
        package_acquirer: Optional[PackageAcquirer] = None,
        acquisition_timeout_seconds: float = DEFAULT_ACQUISITION_TIMEOUT_SECONDS,
    ) -> None:
        self.analyzers = (
            analyzers
            if analyzers is not None
            else [PackageIdentityAnalyzer(), PackageContentAnalyzer()]
        )
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.profile_generator = profile_generator or CompatibilityProfileGenerator()
        self.report_generator = report_generator or ReportGenerator()
        if acquisition_timeout_seconds <= 0:
            raise ValueError("acquisition_timeout_seconds must be positive")
        self.package_acquirer = package_acquirer or get_default_package_acquirer()
        self.acquisition_timeout_seconds = acquisition_timeout_seconds

    async def execute_scan(
        self,
        session: AsyncSession,
        scan_id: UUID,
        package_req: PackageRequest,
    ) -> ScanReport:
        """Run the scan pipeline and persist findings, coverage, and correlations."""
        logger.info(
            "Starting scan %s for %s package '%s'@'%s'",
            scan_id,
            package_req.ecosystem.value,
            package_req.name,
            package_req.version,
        )

        acquired_package: AcquiredPackage | None = None
        try:
            await repository.update_scan_status(session, scan_id, "fetching")
            await session.commit()

            analyzer_results: List[AnalyzerResult] = []
            collected_findings: List[Finding] = []
            analyzer_statuses: Dict[str, str] = {}
            analyzer_errors: Dict[str, str] = {}

            candidate: AcquiredPackage | None = None
            try:
                candidate = await asyncio.wait_for(
                    self.package_acquirer.acquire(package_req),
                    timeout=self.acquisition_timeout_seconds,
                )
                if (
                    candidate.ecosystem != package_req.ecosystem.value
                    or candidate.version != package_req.version
                    or _package_name_key(
                        candidate.package_name,
                        candidate.ecosystem,
                    )
                    != _package_name_key(
                        package_req.name,
                        package_req.ecosystem.value,
                    )
                ):
                    candidate.cleanup()
                    candidate = None
                    raise AcquisitionError(
                        "Acquirer returned an artifact that does not match the request"
                    )
                acquired_package = candidate
                candidate = None
            except (AcquisitionError, TimeoutError) as err:
                if candidate is not None:
                    candidate.cleanup()
                message = (
                    f"Package acquisition timed out after "
                    f"{self.acquisition_timeout_seconds:g} seconds"
                    if isinstance(err, TimeoutError)
                    else f"Package acquisition failed: {err}"
                )
                logger.warning(
                    "Acquisition failed for scan %s: %s",
                    scan_id,
                    message,
                    exc_info=True,
                )
                acquisition_result = AnalyzerResult(
                    analyzer_name="package_acquisition",
                    stage_key="acquisition",
                    status=AnalyzerStatus.FAILED,
                    error_message=message,
                )
            except Exception as err:
                if candidate is not None:
                    candidate.cleanup()
                logger.error(
                    "Unexpected acquisition failure for scan %s: %s",
                    scan_id,
                    err,
                    exc_info=True,
                )
                acquisition_result = AnalyzerResult(
                    analyzer_name="package_acquisition",
                    stage_key="acquisition",
                    status=AnalyzerStatus.FAILED,
                    error_message=f"Unexpected package acquisition error: {err}",
                )

            if acquired_package is not None:
                scan = await repository.get_scan(session, scan_id)
                if scan is not None and scan.package_version is not None:
                    await repository.get_or_create_package_version(
                        session,
                        scan.package_version.package_id,
                        scan.package_version.version,
                        acquired_package.archive_sha256,
                    )
                await session.commit()
                acquisition_result = AnalyzerResult(
                    analyzer_name="package_acquisition",
                    stage_key="acquisition",
                    status=AnalyzerStatus.COMPLETED,
                    metadata={
                        "archive_sha256": acquired_package.archive_sha256,
                        "warnings": acquired_package.warnings,
                        "skipped_files": [
                            item.model_dump()
                            for item in acquired_package.skipped_files
                        ],
                    },
                )

            analyzer_results.append(acquisition_result)
            analyzer_statuses[acquisition_result.stage_key] = acquisition_result.status.value
            if acquisition_result.error_message:
                analyzer_errors[acquisition_result.stage_key] = acquisition_result.error_message

            await repository.update_scan_status(session, scan_id, "analyzing")
            await session.commit()

            for analyzer in self.analyzers:
                if (
                    acquired_package is None
                    and getattr(analyzer, "requires_package_contents", False)
                ):
                    result = AnalyzerResult(
                        analyzer_name=analyzer.name,
                        stage_key=analyzer.stage_key,
                        status=AnalyzerStatus.SKIPPED,
                        error_message=(
                            "Package analysis skipped because acquisition did not "
                            "produce an artifact."
                        ),
                    )
                elif not analyzer.is_available:
                    result = AnalyzerResult(
                        analyzer_name=analyzer.name,
                        stage_key=analyzer.stage_key,
                        status=AnalyzerStatus.NOT_AVAILABLE,
                        error_message="Analyzer module is not available for this scan input.",
                    )
                else:
                    try:
                        result = await analyzer.analyze(package_req, acquired_package)
                    except Exception as err:
                        logger.error(
                            "Analyzer '%s' failed: %s",
                            analyzer.name,
                            err,
                            exc_info=True,
                        )
                        result = AnalyzerResult(
                            analyzer_name=analyzer.name,
                            stage_key=analyzer.stage_key,
                            status=AnalyzerStatus.FAILED,
                            error_message=f"Analyzer error: {err}",
                        )

                analyzer_results.append(result)
                analyzer_statuses[result.stage_key] = result.status.value
                if result.error_message:
                    analyzer_errors[result.stage_key] = result.error_message
                if result.status == AnalyzerStatus.COMPLETED:
                    collected_findings.extend(result.findings)

            aggregated_evidence = aggregate_evidence(collected_findings)
            correlations = self.correlation_engine.correlate(aggregated_evidence)
            compatibility_profile = self.profile_generator.generate(
                analyzer_results=analyzer_results,
                all_analyzers=self.analyzers,
            )

            if collected_findings:
                await repository.save_findings(session, scan_id, collected_findings)

            now = datetime.now(timezone.utc)
            package_info = PackageInfo(
                name=package_req.name,
                ecosystem=package_req.ecosystem.value,
                version=package_req.version,
                archive_hash=(
                    acquired_package.archive_sha256 if acquired_package else None
                ),
            )
            report = self.report_generator.generate_report(
                scan_id=scan_id,
                package=package_info,
                evidence=aggregated_evidence,
                correlations=correlations,
                compatibility_profile=compatibility_profile,
                analyzer_execution_statuses=analyzer_statuses,
                analyzer_errors=analyzer_errors,
                created_at=now,
                completed_at=now,
            )

            await repository.save_scan_results(
                session=session,
                scan_id=scan_id,
                completed_at=now,
                status="completed",
                summary=report.summary,
                correlations_json=[item.model_dump() for item in correlations],
                compatibility_profile_json=compatibility_profile.model_dump(),
                analyzer_statuses_json=analyzer_statuses,
                analyzer_errors_json=analyzer_errors,
            )
            await session.commit()

            logger.info(
                "Scan %s completed with %d unique finding(s); analysis_complete=%s",
                scan_id,
                aggregated_evidence.unique_findings_count,
                report.analysis_complete,
            )
            return report

        except Exception as exc:
            logger.error("Scan %s execution failed: %s", scan_id, exc, exc_info=True)
            try:
                await repository.update_scan_status(session, scan_id, "failed")
                await session.commit()
            except Exception as commit_err:
                logger.error("Failed to mark scan %s as failed: %s", scan_id, commit_err)
            raise
        finally:
            if acquired_package is not None:
                acquired_package.cleanup()
