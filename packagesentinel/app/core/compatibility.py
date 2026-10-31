from typing import Dict, List
from app.detection.analyzers import AnalyzerResult, AnalyzerStatus, BaseAnalyzer
from app.schemas.report import CompatibilityProfile

# Standard set of applicable analysis stages for PackageSentinel platform
STANDARD_APPLICABLE_STAGES: List[str] = [
    "static_analysis",
    "metadata_analysis",
    "behavioral_analysis",
    "dependency_analysis",
]


class CompatibilityProfileGenerator:
    """Generates compatibility profiles reflecting stage availability and test coverage."""

    def __init__(self, applicable_stages: List[str] | None = None) -> None:
        self.applicable_stages = applicable_stages or STANDARD_APPLICABLE_STAGES

    def generate(
        self,
        analyzer_results: List[AnalyzerResult],
        all_analyzers: List[BaseAnalyzer] | None = None,
    ) -> CompatibilityProfile:
        """Calculate dynamic stage statuses and coverage metric.

        Coverage is calculated as:
            (number of completed stages / total applicable stages) * 100
        """
        stages: Dict[str, str] = {}
        for res in analyzer_results:
            stages[res.stage_key] = res.status.value if hasattr(res.status, "value") else str(res.status)
        if all_analyzers:
            for analyzer in all_analyzers:
                if analyzer.stage_key not in stages:
                    if not analyzer.is_available:
                        stages[analyzer.stage_key] = AnalyzerStatus.NOT_AVAILABLE.value
                    else:
                        stages[analyzer.stage_key] = AnalyzerStatus.SKIPPED.value

        # 3. Ensure all standard applicable stages exist in the dictionary
        for stage_key in self.applicable_stages:
            if stage_key not in stages:
                stages[stage_key] = AnalyzerStatus.NOT_AVAILABLE.value

        # 4. Calculate dynamic coverage
        total_applicable = len(self.applicable_stages)
        completed_count = sum(
            1 for stage in self.applicable_stages if stages.get(stage) == AnalyzerStatus.COMPLETED.value
        )

        coverage = round((completed_count / total_applicable) * 100.0, 1) if total_applicable > 0 else 0.0

        return CompatibilityProfile(
            stages=stages,
            coverage=coverage,
        )
