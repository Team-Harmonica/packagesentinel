"""Tests for SQLAlchemy database operations and repository layer."""

from datetime import datetime, timezone
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from app.database import repository
from app.database.models import PackageVersion
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
    v1 = await repository.get_or_create_package_version(
        db_session,
        pkg.id,
        "4.17.21",
        archive_hash="first-hash",
    )
    assert v1.id is not None
    assert v1.package_id == pkg.id
    assert v1.version == "4.17.21"
    assert v1.archive_hash == "first-hash"

    # Idempotent version lookup
    v1_same = await repository.get_or_create_package_version(
        db_session,
        pkg.id,
        "4.17.21",
        archive_hash="first-hash",
    )
    assert v1_same.id == v1.id
    version_count = await db_session.scalar(
        select(func.count()).select_from(PackageVersion).where(
            PackageVersion.package_id == pkg.id,
            PackageVersion.version == "4.17.21",
        )
    )
    assert version_count == 1


@pytest.mark.asyncio
async def test_existing_package_version_archive_hash_is_updated(db_session: AsyncSession):
    pkg = await repository.get_or_create_package(db_session, "hash-update", "npm")
    version = await repository.get_or_create_package_version(
        db_session,
        pkg.id,
        "1.0.0",
        archive_hash="old-hash",
    )

    updated = await repository.get_or_create_package_version(
        db_session,
        pkg.id,
        "1.0.0",
        archive_hash="new-hash",
    )

    assert updated.id == version.id
    assert updated.package_id == pkg.id
    assert updated.archive_hash == "new-hash"
    version_count = await db_session.scalar(
        select(func.count()).select_from(PackageVersion).where(
            PackageVersion.package_id == pkg.id,
            PackageVersion.version == "1.0.0",
        )
    )
    assert version_count == 1


@pytest.mark.asyncio
async def test_missing_archive_hash_does_not_clear_existing_hash(db_session: AsyncSession):
    pkg = await repository.get_or_create_package(db_session, "hash-preserve", "pypi")
    version = await repository.get_or_create_package_version(
        db_session,
        pkg.id,
        "2.0.0",
        archive_hash="known-hash",
    )

    fetched = await repository.get_or_create_package_version(
        db_session,
        pkg.id,
        "2.0.0",
    )

    assert fetched.id == version.id
    assert fetched.archive_hash == "known-hash"


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
