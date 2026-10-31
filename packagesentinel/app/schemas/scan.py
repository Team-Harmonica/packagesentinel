"""Scan request, status, and response schemas."""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field
from app.schemas.package import PackageInfo


class ScanStatus(str, Enum):
    """Lifecycle statuses for a package scan."""
    QUEUED = "queued"
    FETCHING = "fetching"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanResponse(BaseModel):
    """Immediate response payload returned upon scan dispatch."""

    scan_id: UUID = Field(
        ...,
        description="Unique identifier (UUID) assigned to the scan job",
    )
    status: ScanStatus = Field(
        ...,
        description="Current lifecycle status of the scan",
    )
    message: str = Field(
        ...,
        description="Human-readable informational message",
        examples=["Scan queued successfully"],
    )


class ScanStatusDetails(BaseModel):
    """Detailed scan status representation for polling and tracking."""

    scan_id: UUID
    status: ScanStatus
    message: str
    package: Optional[PackageInfo] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
