from typing import Dict, List, Sequence

from app.detection.analyzers import AnalyzerResult, AnalyzerStatus, BaseAnalyzer
from app.schemas.report import CompatibilityProfile, STANDARD_ANALYSIS_STAGES


def calculate_stage_coverage(
    stages: Dict[str, str],
    applicable_stages: Sequence[str],
) -> float:
    """Return the percentage of applicable stages that completed successfully."""
    if not applicable_stages:
        return 0.0
    completed = sum(
        stages.get(stage) == AnalyzerStatus.COMPLETED.value
        for stage in applicable_stages
    )
    return round(completed / len(applicable_stages) * 100.0, 1)


def analysis_stages_complete(
    stages: Dict[str, str],
    applicable_stages: Sequence[str],
) -> bool:
    """A scan is fully analyzed only when every applicable stage completed."""
    return bool(applicable_stages) and all(
        stages.get(stage) == AnalyzerStatus.COMPLETED.value
        for stage in applicable_stages
    )


class CompatibilityProfileGenerator:
    """Generate stage statuses and coverage for the configured analysis stages."""

    def __init__(self, applicable_stages: List[str] | None = None) -> None:
        self.applicable_stages = (
            list(STANDARD_ANALYSIS_STAGES)
            if applicable_stages is None
            else list(applicable_stages)
        )

    def generate(
        self,
        analyzer_results: List[AnalyzerResult],
        all_analyzers: List[BaseAnalyzer] | None = None,
    ) -> CompatibilityProfile:
        """Return all known stage statuses and coverage over applicable stages."""
        stages: Dict[str, str] = {}
        for res in analyzer_results:
            status = res.status.value if hasattr(res.status, "value") else str(res.status)
            stages[res.stage_key] = (
                AnalyzerStatus.UNAVAILABLE.value
                if status == "not_available"
                else status
            )

        if all_analyzers:
            for analyzer in all_analyzers:
                if analyzer.stage_key not in stages:
                    if not analyzer.is_available:
                        stages[analyzer.stage_key] = AnalyzerStatus.UNAVAILABLE.value
                    else:
                        stages[analyzer.stage_key] = AnalyzerStatus.SKIPPED.value

        for stage_key in STANDARD_ANALYSIS_STAGES:
            if stage_key not in stages:
                stages[stage_key] = AnalyzerStatus.UNAVAILABLE.value

        return CompatibilityProfile(
            stages=stages,
            applicable_stages=self.applicable_stages,
            coverage=calculate_stage_coverage(stages, self.applicable_stages),
        )
