"""Tests for compatibility profile generation and dynamic coverage calculation."""

from app.core.compatibility import CompatibilityProfileGenerator
from app.detection.analyzers import AnalyzerResult, AnalyzerStatus


def test_compatibility_profile_coverage_calculation():
    """Verify coverage is computed dynamically from applicable stages."""
    generator = CompatibilityProfileGenerator(
        applicable_stages=[
            "static_analysis",
            "metadata_analysis",
            "behavioral_analysis",
            "dependency_analysis",
        ]
    )

    results = [
        AnalyzerResult(
            analyzer_name="static_analysis",
            stage_key="static_analysis",
            status=AnalyzerStatus.COMPLETED,
        ),
        AnalyzerResult(
            analyzer_name="metadata_analysis",
            stage_key="metadata_analysis",
            status=AnalyzerStatus.COMPLETED,
        ),
        AnalyzerResult(
            analyzer_name="behavioral_analysis",
            stage_key="behavioral_analysis",
            status=AnalyzerStatus.NOT_AVAILABLE,
        ),
        AnalyzerResult(
            analyzer_name="dependency_analysis",
            stage_key="dependency_analysis",
            status=AnalyzerStatus.NOT_AVAILABLE,
        ),
    ]

    profile = generator.generate(results)

    # 2 out of 4 completed = 50.0% coverage
    assert profile.coverage == 50.0
    assert profile.stages["static_analysis"] == "completed"
    assert profile.stages["metadata_analysis"] == "completed"
    assert profile.stages["behavioral_analysis"] == "not_available"
    assert profile.stages["dependency_analysis"] == "not_available"


def test_coverage_drops_when_stage_fails():
    """Verify failed stages are not counted as completed in coverage metric."""
    generator = CompatibilityProfileGenerator(
        applicable_stages=["static_analysis", "metadata_analysis", "behavioral_analysis", "dependency_analysis"]
    )

    results = [
        AnalyzerResult(
            analyzer_name="static_analysis",
            stage_key="static_analysis",
            status=AnalyzerStatus.FAILED,
            error_message="Parser crash",
        ),
        AnalyzerResult(
            analyzer_name="metadata_analysis",
            stage_key="metadata_analysis",
            status=AnalyzerStatus.COMPLETED,
        ),
    ]

    profile = generator.generate(results)

    # Only 1 completed out of 4 -> 25.0%
    assert profile.coverage == 25.0
    assert profile.stages["static_analysis"] == "failed"
