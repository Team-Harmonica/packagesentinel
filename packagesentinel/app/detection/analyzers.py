"""Adapters between the integrated static scanner and PackageSentinel."""

import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.detection.scanner import Finding as DetectorFinding
from app.detection.scanner import run_scanner
from app.schemas.finding import Finding, Severity
from app.schemas.package import PackageRequest


class AnalyzerStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_AVAILABLE = "not_available"


class AnalyzerResult(BaseModel):
    analyzer_name: str
    stage_key: str
    status: AnalyzerStatus
    findings: List[Finding] = Field(default_factory=list)
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BaseAnalyzer:
    name = "static_analysis"
    stage_key = "static_analysis"

    @property
    def is_available(self) -> bool:
        return True

    async def analyze(self, package: PackageRequest) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            stage_key=self.stage_key,
            status=AnalyzerStatus.NOT_AVAILABLE,
            error_message=(
                "Package contents are not available; package acquisition or upload "
                "must be implemented before static analysis can run."
            ),
        )


class PackageContentAnalyzer(BaseAnalyzer):
    """Run the Harmonica static detectors when an unpacked directory is supplied."""

    CATEGORY_BY_CHECK = {
        "credential_access": "credential_access",
        "network_exfil": "network_exfiltration",
        "dangerous_call": "suspicious_execution",
        "dynamic_fetch": "suspicious_execution",
        "obfuscation": "obfuscation",
        "glassworm": "obfuscation",
        "capability": "capability_profile",
    }
    SEVERITY_BY_DETECTOR = {
        "info": Severity.LOW,
        "suspicious": Severity.MEDIUM,
        "malicious": Severity.CRITICAL,
    }
    CONFIDENCE_BY_DETECTOR = {
        "info": 1.0,
        "suspicious": 0.8,
        "malicious": 0.95,
    }

    @classmethod
    def _convert_finding(cls, item: DetectorFinding) -> Finding:
        location = re.match(r"^(.*?):(\d+)(?::\d+)?(?: \(.*\))?$", item.location)
        return Finding(
            rule_id=f"HARMONICA-{item.check.upper()}",
            category=cls.CATEGORY_BY_CHECK.get(item.check, item.check),
            severity=cls.SEVERITY_BY_DETECTOR[item.severity],
            confidence=cls.CONFIDENCE_BY_DETECTOR[item.severity],
            file=location.group(1) if location else item.location or None,
            line=int(location.group(2)) if location else None,
            evidence=item.message,
            source="harmonica_static",
            metadata={
                "detector": item.check,
                "detector_weight": item.weight,
            },
        )

    @classmethod
    def analyze_directory(
        cls,
        package_dir: Path | str,
        metadata: Optional[dict] = None,
    ) -> List[Finding]:
        return [
            cls._convert_finding(item)
            for item in run_scanner(package_dir, metadata or {})
        ]
