"""Evidence aggregation module for normalizing, deduplicating, and clustering findings."""

from collections import defaultdict
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.schemas.finding import Finding, Severity


SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DeduplicatedFinding(BaseModel):
    """Normalized finding representing one or more corroborating analyzer reports."""

    rule_id: str
    category: str
    severity: Severity
    confidence: float
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: str
    primary_source: str
    sources: List[str] = Field(default_factory=list)
    corroboration_count: int = 1
    original_findings: List[Finding] = Field(default_factory=list)


class AggregatedEvidence(BaseModel):
    """Structured container for aggregated, deduplicated, and categorized evidence."""

    raw_findings: List[Finding] = Field(
        default_factory=list,
        description="Preserved raw findings exactly as emitted by analyzers",
    )
    unique_findings: List[DeduplicatedFinding] = Field(
        default_factory=list,
        description="Deduplicated findings with multi-source corroboration metadata",
    )
    findings_by_category: Dict[str, List[DeduplicatedFinding]] = Field(
        default_factory=dict,
        description="Deduplicated findings clustered by security category",
    )
    findings_by_severity: Dict[str, List[DeduplicatedFinding]] = Field(
        default_factory=dict,
        description="Deduplicated findings clustered by severity level",
    )
    severity_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of unique findings per severity string",
    )
    sources_by_rule: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Analyzers that contributed to each rule ID",
    )
    total_raw_findings: int = 0
    unique_findings_count: int = 0


def _compute_finding_fingerprint(f: Finding) -> str:
    """Compute a deterministic hash/key to identify identical findings across analyzers."""
    # Findings targeting the same rule, category, file and line are treated as duplicates
    # If file/line are missing, we fingerprint on rule_id, category, and normalized evidence text.
    norm_file = (f.file or "").strip().lower()
    norm_line = str(f.line or 0)
    norm_evidence = " ".join(f.evidence.strip().lower().split())
    return f"{f.rule_id}|{f.category}|{norm_file}|{norm_line}|{norm_evidence}"


def aggregate_evidence(raw_findings: List[Finding]) -> AggregatedEvidence:
    """Aggregate raw findings: cluster by category, deduplicate, and record corroborating sources.

    Requirements addressed:
    - Group findings by category.
    - Preserve individual findings (stored in raw_findings and within each DeduplicatedFinding).
    - Identify which analyzers generated each finding.
    - Avoid counting duplicate findings repeatedly.
    - Preserve maximum severity and highest confidence.
    - Return structured aggregated evidence.
    """
    fingerprint_groups: Dict[str, List[Finding]] = defaultdict(list)
    sources_by_rule: Dict[str, Set[str]] = defaultdict(set)

    for finding in raw_findings:
        fp = _compute_finding_fingerprint(finding)
        fingerprint_groups[fp].append(finding)
        sources_by_rule[finding.rule_id].add(finding.source)

    unique_findings: List[DeduplicatedFinding] = []

    for _, group in fingerprint_groups.items():
        primary = group[0]
        # Preserve all distinct sources that corroborated this finding
        sources = list(dict.fromkeys(f.source for f in group))

        # Preserve highest severity
        highest_severity = max(
            (f.severity for f in group),
            key=lambda s: SEVERITY_ORDER.get(s, 0),
        )

        # Preserve highest confidence score
        highest_confidence = max(f.confidence for f in group)

        deduped = DeduplicatedFinding(
            rule_id=primary.rule_id,
            category=primary.category,
            severity=highest_severity,
            confidence=highest_confidence,
            file=primary.file,
            line=primary.line,
            evidence=primary.evidence,
            primary_source=primary.source,
            sources=sources,
            corroboration_count=len(sources),
            original_findings=group,
        )
        unique_findings.append(deduped)

    # Group by category and severity
    findings_by_category: Dict[str, List[DeduplicatedFinding]] = defaultdict(list)
    findings_by_severity: Dict[str, List[DeduplicatedFinding]] = defaultdict(list)

    severity_counts: Dict[str, int] = {
        Severity.LOW.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.HIGH.value: 0,
        Severity.CRITICAL.value: 0,
    }

    for df in unique_findings:
        findings_by_category[df.category].append(df)
        sev_key = df.severity.value if hasattr(df.severity, "value") else str(df.severity)
        findings_by_severity[sev_key].append(df)
        severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

    return AggregatedEvidence(
        raw_findings=list(raw_findings),
        unique_findings=unique_findings,
        findings_by_category=dict(findings_by_category),
        findings_by_severity=dict(findings_by_severity),
        severity_counts=severity_counts,
        sources_by_rule={k: sorted(v) for k, v in sources_by_rule.items()},
        total_raw_findings=len(raw_findings),
        unique_findings_count=len(unique_findings),
    )

