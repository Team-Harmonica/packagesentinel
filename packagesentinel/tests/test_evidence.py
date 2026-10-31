"""Tests for evidence aggregation and duplicate finding handling."""

from app.core.evidence import aggregate_evidence
from app.schemas.finding import Finding, Severity


def test_evidence_grouping_by_category():
    """Verify findings are clustered by category."""
    raw = [
        Finding(
            rule_id="R1",
            category="credential_access",
            severity=Severity.HIGH,
            confidence=0.8,
            evidence="Key read",
            source="analyzer_a",
        ),
        Finding(
            rule_id="R2",
            category="network_exfiltration",
            severity=Severity.CRITICAL,
            confidence=0.9,
            evidence="POST sent",
            source="analyzer_b",
        ),
    ]

    agg = aggregate_evidence(raw)
    assert agg.total_raw_findings == 2
    assert agg.unique_findings_count == 2
    assert "credential_access" in agg.findings_by_category
    assert "network_exfiltration" in agg.findings_by_category
    assert len(agg.findings_by_category["credential_access"]) == 1


def test_duplicate_finding_handling_and_corroboration():
    """Verify duplicate findings from multiple analyzers are deduplicated and corroborated."""
    raw = [
        # Analyzer 1 reports finding
        Finding(
            rule_id="DUP-001",
            category="obfuscation",
            severity=Severity.MEDIUM,
            confidence=0.7,
            file="index.js",
            line=10,
            evidence="eval(atob(x)) executed",
            source="static_analysis",
        ),
        # Analyzer 2 reports exact same finding with higher confidence and severity
        Finding(
            rule_id="DUP-001",
            category="obfuscation",
            severity=Severity.HIGH,
            confidence=0.85,
            file="index.js",
            line=10,
            evidence="eval(atob(x)) executed",
            source="metadata_analysis",
        ),
    ]

    agg = aggregate_evidence(raw)
    assert agg.total_raw_findings == 2
    # Only 1 unique finding should remain
    assert agg.unique_findings_count == 1

    unique = agg.unique_findings[0]
    # Highest severity should be preserved
    assert unique.severity == Severity.HIGH
    # Highest confidence should be preserved
    assert unique.confidence == 0.85
    # Corroborating sources must be recorded
    assert sorted(unique.sources) == ["metadata_analysis", "static_analysis"]
    assert unique.corroboration_count == 2
    # Raw original findings must be preserved
    assert len(unique.original_findings) == 2


def test_severity_counts_accuracy():
    """Verify finding counts grouped by severity."""
    raw = [
        Finding(rule_id="R1", category="c1", severity=Severity.LOW, confidence=0.5, evidence="e1", source="s1"),
        Finding(rule_id="R2", category="c2", severity=Severity.MEDIUM, confidence=0.6, evidence="e2", source="s1"),
        Finding(rule_id="R3", category="c3", severity=Severity.HIGH, confidence=0.7, evidence="e3", source="s1"),
        Finding(rule_id="R4", category="c4", severity=Severity.CRITICAL, confidence=0.9, evidence="e4", source="s1"),
    ]

    agg = aggregate_evidence(raw)
    assert agg.severity_counts["low"] == 1
    assert agg.severity_counts["medium"] == 1
    assert agg.severity_counts["high"] == 1
    assert agg.severity_counts["critical"] == 1

