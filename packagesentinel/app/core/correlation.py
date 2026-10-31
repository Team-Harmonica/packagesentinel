"""Rule-based correlation engine for detecting multi-stage and compound malicious patterns."""

from dataclasses import dataclass
from typing import List, Set
from app.core.evidence import AggregatedEvidence
from app.schemas.finding import Finding, Severity
from app.schemas.report import CorrelationResult


@dataclass(frozen=True)
class CorrelationRule:
    """Definition of a multi-category correlation heuristic rule."""

    rule_id: str
    category: str
    severity: Severity
    description: str
    required_categories: Set[str]


# Predefined baseline correlation rules as specified in Section 8
BASELINE_CORRELATION_RULES: List[CorrelationRule] = [
    CorrelationRule(
        rule_id="CORR-CRED-EXFIL",
        category="credential_exfiltration",
        severity=Severity.CRITICAL,
        description=(
            "Potential credential theft detected: sensitive credential harvesting "
            "combined with outbound network exfiltration."
        ),
        required_categories={"credential_access", "network_exfiltration"},
    ),
    CorrelationRule(
        rule_id="CORR-OBF-EXEC",
        category="obfuscated_execution",
        severity=Severity.HIGH,
        description=(
            "Evasive execution pattern detected: runtime payload obfuscation "
            "combined with suspicious dynamic execution."
        ),
        required_categories={"obfuscation", "suspicious_execution"},
    ),
    CorrelationRule(
        rule_id="CORR-INSTALL-EXEC",
        category="suspicious_installation",
        severity=Severity.HIGH,
        description=(
            "Dangerous install lifecycle detected: suspicious package install hook "
            "combined with dynamic process execution."
        ),
        required_categories={"suspicious_install_script", "suspicious_execution"},
    ),
]


class CorrelationEngine:
    """Evaluates aggregated evidence against compound security correlation rules."""

    def __init__(self, rules: List[CorrelationRule] | None = None) -> None:
        self.rules = rules if rules is not None else BASELINE_CORRELATION_RULES

    def correlate(self, evidence: AggregatedEvidence) -> List[CorrelationResult]:
        """Inspect aggregated findings and return triggered compound correlation patterns.

        Note: Correlations represent supporting evidence of complex attack patterns
        rather than standalone single-point detections.
        """
        active_categories = set(evidence.findings_by_category.keys())
        results: List[CorrelationResult] = []

        for rule in self.rules:
            # Check if all prerequisite categories are present
            if rule.required_categories.issubset(active_categories):
                # Gather contributing findings from the prerequisite categories
                contributing: List[Finding] = []
                for cat in rule.required_categories:
                    for df in evidence.findings_by_category.get(cat, []):
                        # Convert to base Finding schema
                        contributing.append(
                            Finding(
                                rule_id=df.rule_id,
                                category=df.category,
                                severity=df.severity,
                                confidence=df.confidence,
                                file=df.file,
                                line=df.line,
                                evidence=df.evidence,
                                source=df.primary_source,
                                metadata={"corroborating_sources": df.sources},
                            )
                        )

                results.append(
                    CorrelationResult(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        contributing_findings=contributing,
                    )
                )

        return results

