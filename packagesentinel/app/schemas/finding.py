"""Security finding schemas and severity definitions."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized finding severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Normalized security finding emitted by detection analyzers."""

    rule_id: str = Field(
        ...,
        description="Identifier of the detection rule triggered",
        examples=["CRED-001"],
    )
    category: str = Field(
        ...,
        description="Category classification (e.g., 'credential_access', 'network_exfiltration')",
        examples=["credential_access"],
    )
    severity: Severity = Field(
        ...,
        description="Finding severity level (low, medium, high, critical)",
        examples=["high"],
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for this finding between 0.0 and 1.0",
        examples=[0.85],
    )
    file: Optional[str] = Field(
        default=None,
        description="Relative file path where the finding was identified",
        examples=["index.js"],
    )
    line: Optional[int] = Field(
        default=None,
        ge=1,
        description="Line number in the file where the evidence was located",
        examples=[42],
    )
    evidence: str = Field(
        ...,
        description="Human-readable evidence snippet or descriptive proof",
        examples=["process.env.AWS_SECRET_ACCESS_KEY accessed"],
    )
    source: str = Field(
        ...,
        description="Name of the analyzer or module that produced this finding",
        examples=["static_analysis"],
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional additional analyzer-specific metadata",
    )

