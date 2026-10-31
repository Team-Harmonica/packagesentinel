"""Asynchronous scan orchestration, evidence aggregation, and report persistence."""

from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compatibility import CompatibilityProfileGenerator
from app.core.correlation import CorrelationEngine
from app.core.evidence import aggregate_evidence
from app.database import repository
from app.detection.analyzers import (
    AnalyzerResult,
    AnalyzerStatus,
    BaseAnalyzer,
    PackageContentAnalyzer,
)
from app.schemas.finding import Finding
from app.schemas.package import PackageInfo, PackageRequest
from app.schemas.report import ScanReport
from app.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Run configured analyzers and persist their findings and report metadata."""

    def __init__(
        self,
        analyzers: Optional[List[BaseAnalyzer]] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        profile_generator: Optional[CompatibilityProfileGenerator] = None,
        report_generator: Optional[ReportGenerator] = None,
    ) -> None:
        self.analyzers = analyzers if analyzers is not None else [PackageContentAnalyzer()]
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.profile_generator = profile_generator or CompatibilityProfileGenerator()
        self.report_generator = report_generator or ReportGenerator()

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

        try:
            await repository.update_scan_status(session, scan_id, "fetching")
            await session.commit()
            await repository.update_scan_status(session, scan_id, "analyzing")
            await session.commit()

            analyzer_results: List[AnalyzerResult] = []
            collected_findings: List[Finding] = []
            analyzer_statuses: Dict[str, str] = {}
            analyzer_errors: Dict[str, str] = {}

            for analyzer in self.analyzers:
                if not analyzer.is_available:
                    result = AnalyzerResult(
                        analyzer_name=analyzer.name,
                        stage_key=analyzer.stage_key,
                        status=AnalyzerStatus.NOT_AVAILABLE,
                        error_message="Analyzer module is not available for this scan input.",
                    )
                else:
                    try:
                        result = await analyzer.analyze(package_req)
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
