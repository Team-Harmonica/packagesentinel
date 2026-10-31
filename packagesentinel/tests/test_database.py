"""Tests for SQLAlchemy database operations and repository layer."""

from datetime import datetime, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from app.database import repository
from app.schemas.finding import Finding, Severity


@pytest.mark.asyncio
async def test_package_and_version_creation(db_session: AsyncSession):
    """Verify package and package version creation and idempotency."""
    pkg = await repository.get_or_create_package(db_session, "lodash", "npm")
    assert pkg.id is not None
    assert pkg.name == "lodash"
    assert pkg.ecosystem == "npm"

    # Subsequent lookup should return existing record
    pkg_same = await repository.get_or_create_package(db_session, "lodash", "npm")
    assert pkg_same.id == pkg.id

    # Create version
    v1 = await repository.get_or_create_package_version(db_session, pkg.id, "4.17.21")
    assert v1.id is not None
    assert v1.package_id == pkg.id
    assert v1.version == "4.17.21"

    # Idempotent version lookup
    v1_same = await repository.get_or_create_package_version(db_session, pkg.id, "4.17.21")
    assert v1_same.id == v1.id


@pytest.mark.asyncio
async def test_scan_lifecycle_crud(db_session: AsyncSession):
    """Verify scan creation, status transitions, and data retrieval."""
    pkg = await repository.get_or_create_package(db_session, "requests", "pypi")
    version = await repository.get_or_create_package_version(db_session, pkg.id, "2.31.0")

    # 1. Create scan
    scan = await repository.create_scan(db_session, version.id, status="queued")
    assert scan.id is not None
    assert scan.status == "queued"

    # 2. Update status
    updated = await repository.update_scan_status(db_session, scan.id, "analyzing")
    assert updated is not None
    assert updated.status == "analyzing"

    # 3. Save findings
    findings = [
        Finding(
            rule_id="RULE-1",
            category="network",
            severity=Severity.MEDIUM,
            confidence=0.8,
            evidence="Outbound socket created",
            source="static_test",
        )
    ]
    saved_findings = await repository.save_findings(db_session, scan.id, findings)
    assert len(saved_findings) == 1
    assert saved_findings[0].rule_id == "RULE-1"

    # 4. Save final results
    now = datetime.now(timezone.utc)
    completed_scan = await repository.save_scan_results(
        session=db_session,
        scan_id=scan.id,
        completed_at=now,
        status="completed",
        summary="Test summary",
    )
    assert completed_scan is not None
    assert completed_scan.status == "completed"
    assert completed_scan.summary == "Test summary"

    # 5. Retrieve with findings
    fetched = await repository.get_scan_with_findings(db_session, scan.id)
    assert fetched is not None
    assert len(fetched.findings) == 1
    assert fetched.package_version.package.name == "requests"
