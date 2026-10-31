"""Tests for the rule-based correlation engine."""

from app.core.correlation import CorrelationEngine
from app.core.evidence import aggregate_evidence
from app.schemas.finding import Finding, Severity


def test_credential_exfiltration_correlation():
    """Verify combination of credential_access and network_exfiltration triggers correlation."""
    raw = [
        Finding(
            rule_id="CRED-001",
            category="credential_access",
            severity=Severity.HIGH,
            confidence=0.9,
            evidence="Reading environment secrets",
            source="static_analysis",
        ),
        Finding(
            rule_id="NET-001",
            category="network_exfiltration",
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence="Sending payload to remote server",
            source="static_analysis",
        ),
    ]

    agg = aggregate_evidence(raw)
    engine = CorrelationEngine()
    correlations = engine.correlate(agg)

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr.rule_id == "CORR-CRED-EXFIL"
    assert corr.category == "credential_exfiltration"
    assert corr.severity == Severity.CRITICAL
    assert len(corr.contributing_findings) == 2


def test_obfuscated_execution_correlation():
    """Verify combination of obfuscation and suspicious_execution triggers correlation."""
    raw = [
        Finding(
            rule_id="OBF-001",
            category="obfuscation",
            severity=Severity.MEDIUM,
            confidence=0.8,
            evidence="Base64 payload",
            source="static_analysis",
        ),
        Finding(
            rule_id="EXE-001",
            category="suspicious_execution",
            severity=Severity.HIGH,
            confidence=0.85,
            evidence="Child process spawned",
            source="static_analysis",
        ),
    ]

    agg = aggregate_evidence(raw)
    engine = CorrelationEngine()
    correlations = engine.correlate(agg)

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr.rule_id == "CORR-OBF-EXEC"
    assert corr.category == "obfuscated_execution"
    assert corr.severity == Severity.HIGH


def test_suspicious_installation_correlation():
    """Verify combination of suspicious_install_script and suspicious_execution."""
    raw = [
        Finding(
            rule_id="INS-001",
            category="suspicious_install_script",
            severity=Severity.MEDIUM,
            confidence=0.75,
            evidence="Preinstall hook curl",
            source="metadata_analysis",
        ),
        Finding(
            rule_id="EXE-001",
            category="suspicious_execution",
            severity=Severity.HIGH,
            confidence=0.8,
            evidence="Exec call in script",
            source="static_analysis",
        ),
    ]

    agg = aggregate_evidence(raw)
    engine = CorrelationEngine()
    correlations = engine.correlate(agg)

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr.rule_id == "CORR-INSTALL-EXEC"
    assert corr.category == "suspicious_installation"


def test_unmatched_categories_do_not_correlate():
    """Verify single or unrelated categories do not trigger spurious correlations."""
    raw = [
        Finding(
            rule_id="CRED-001",
            category="credential_access",
            severity=Severity.HIGH,
            confidence=0.9,
            evidence="Only credential access without exfiltration",
            source="static_analysis",
        )
    ]

    agg = aggregate_evidence(raw)
    engine = CorrelationEngine()
    correlations = engine.correlate(agg)

    assert len(correlations) == 0

