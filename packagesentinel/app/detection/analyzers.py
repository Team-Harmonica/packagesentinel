"""Adapters between the integrated static scanner and PackageSentinel."""

from enum import Enum
from importlib import import_module
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from app.acquisition.contracts import AcquiredPackage
from app.detection.scanner import Finding as DetectorFinding
from app.detection.scanner import run_scanner
from app.schemas.finding import Finding, Severity
from app.schemas.package import PackageRequest


class AnalyzerStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    NOT_AVAILABLE = "unavailable"


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

    async def analyze(
        self,
        package: PackageRequest,
        acquired_package: Optional[AcquiredPackage] = None,
    ) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            stage_key=self.stage_key,
            status=AnalyzerStatus.NOT_AVAILABLE,
            error_message=(
                "Package contents are not available; static analysis requires an "
                "acquired package artifact."
            ),
        )


class PackageContentAnalyzer(BaseAnalyzer):
    """Run the integrated static detectors when an unpacked directory is supplied."""

    CATEGORY_BY_CHECK = {
        "credential_access": "credential_access",
        "network_exfil": "network_exfiltration",
        "dangerous_call": "suspicious_execution",
        "dynamic_fetch": "suspicious_execution",
        "obfuscation": "obfuscation",
        "glassworm": "obfuscation",
        "trojan_source_bidi": "obfuscation",
        "stego": "steganography",
        "typosquat": "typosquatting",
        "capability": "capability_profile",
    }
    requires_package_contents = True
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
    def _convert_finding(
        cls,
        item: DetectorFinding,
        source: str = "packagesentinel_static",
    ) -> Finding:
        location = re.match(r"^(.*?):(\d+)(?::\d+)?(?: \(.*\))?$", item.location)
        return Finding(
            rule_id=item.rule_id or f"PACKAGESENTINEL-{item.check.upper()}",
            category=item.category or cls.CATEGORY_BY_CHECK.get(item.check, item.check),
            severity=cls.SEVERITY_BY_DETECTOR[item.severity],
            confidence=(
                item.confidence
                if item.confidence is not None
                else cls.CONFIDENCE_BY_DETECTOR[item.severity]
            ),
            file=location.group(1) if location else item.location or None,
            line=int(location.group(2)) if location else None,
            evidence=item.message,
            source=source,
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

    async def analyze(
        self,
        package: PackageRequest,
        acquired_package: Optional[AcquiredPackage] = None,
    ) -> AnalyzerResult:
        if acquired_package is None:
            return await super().analyze(package)

        metadata = {
            **acquired_package.metadata,
            "name": acquired_package.package_name,
            "ecosystem": acquired_package.ecosystem,
            "version": acquired_package.version,
        }
        detector_findings = run_scanner(acquired_package.extracted_dir, metadata)
        findings = [
            self._convert_finding(item)
            for item in detector_findings
            if item.check not in {"metadata", "typosquat"}
        ]
        return AnalyzerResult(
            analyzer_name=self.name,
            stage_key=self.stage_key,
            status=AnalyzerStatus.COMPLETED,
            findings=findings,
            metadata={
                "archive_sha256": acquired_package.archive_sha256,
                "warnings": acquired_package.warnings,
                "skipped_files": [
                    item.model_dump() for item in acquired_package.skipped_files
                ],
            },
        )


class PackageMetadataAnalyzer(BaseAnalyzer):
    """Adapt metadata detection results to the shared analyzer result contract.

    The detection module exposes ``check(package_dir, metadata)`` and returns
    scanner findings, which this adapter normalizes into shared findings.
    """

    name = "package_metadata"
    stage_key = "metadata_analysis"
    requires_package_contents = True

    def __init__(
        self,
        detector: Optional[Callable[[Dict[str, Any]], Sequence[Any]]] = None,
    ) -> None:
        self._detector = detector

    def _get_detector(self) -> Optional[Callable[..., Sequence[Any]]]:
        if self._detector is not None:
            return self._detector
        try:
            module = import_module("app.detection.metadata")
        except ModuleNotFoundError as exc:
            if exc.name == "app.detection.metadata":
                return None
            raise
        detector = getattr(module, "check", None)
        if detector is None:
            raise AttributeError(
                "app.detection.metadata must expose check(package_dir, metadata)"
            )
        return detector

    @property
    def is_available(self) -> bool:
        return self._get_detector() is not None

    async def analyze(
        self,
        package: PackageRequest,
        acquired_package: Optional[AcquiredPackage] = None,
    ) -> AnalyzerResult:
        detector = self._get_detector()
        if detector is None:
            return AnalyzerResult(
                analyzer_name=self.name,
                stage_key=self.stage_key,
                status=AnalyzerStatus.UNAVAILABLE,
                error_message="Metadata detection module is not available.",
            )
        if acquired_package is None:
            return AnalyzerResult(
                analyzer_name=self.name,
                stage_key=self.stage_key,
                status=AnalyzerStatus.SKIPPED,
                error_message="Metadata analysis requires acquired package metadata.",
            )

        metadata = {
            **acquired_package.metadata,
            "name": acquired_package.package_name,
            "ecosystem": acquired_package.ecosystem,
            "version": acquired_package.version,
        }
        detected = (
            detector(metadata)
            if self._detector is not None
            else detector(acquired_package.extracted_dir, metadata)
        )
        findings = []
        for item in detected:
            if isinstance(item, Finding):
                findings.append(item.model_copy(update={"source": self.stage_key}))
            else:
                findings.append(
                    PackageContentAnalyzer._convert_finding(item, source=self.stage_key)
                )
        return AnalyzerResult(
            analyzer_name=self.name,
            stage_key=self.stage_key,
            status=AnalyzerStatus.COMPLETED,
            findings=findings,
            metadata={"metadata_keys": sorted(metadata)},
        )


class PackageTyposquattingAnalyzer(BaseAnalyzer):
    """Adapt package-name typo detection to the shared analyzer result contract."""

    name = "package_typosquatting"
    stage_key = "typosquatting_analysis"

    async def analyze(
        self,
        package: PackageRequest,
        acquired_package: Optional[AcquiredPackage] = None,
    ) -> AnalyzerResult:
        from app.detection.typosquat import check

        metadata = {
            **(acquired_package.metadata if acquired_package is not None else {}),
            "ecosystem": package.ecosystem.value,
            "name": package.name,
        }
        detector_findings = check(Path(), metadata)
        findings = [
            PackageContentAnalyzer._convert_finding(item, source=self.stage_key)
            for item in detector_findings
        ]
        return AnalyzerResult(
            analyzer_name=self.name,
            stage_key=self.stage_key,
            status=AnalyzerStatus.COMPLETED,
            findings=findings,
            metadata=metadata,
        )


PackageIdentityAnalyzer = PackageTyposquattingAnalyzer
