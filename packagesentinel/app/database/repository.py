"""Database repository layer providing CRUD operations for scans, packages, and findings."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.models import FindingRecord, Package, PackageVersion, Scan
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


async def get_or_create_package(
    session: AsyncSession,
    name: str,
    ecosystem: str,
) -> Package:
    """Find an existing package record or create a new one."""
    stmt = select(Package).where(
        Package.name == name,
        Package.ecosystem == ecosystem,
    )
    result = await session.execute(stmt)
    package = result.scalar_one_or_none()

    if package is None:
        package = Package(name=name, ecosystem=ecosystem)
        session.add(package)
        await session.flush()
        logger.debug("Created package record: %s/%s (id=%s)", ecosystem, name, package.id)

    return package


async def get_or_create_package_version(
    session: AsyncSession,
    package_id: int,
    version: str,
    archive_hash: Optional[str] = None,
) -> PackageVersion:
    """Find or create a package version and persist any newly acquired hash.

    The unique package/version constraint remains the source of truth when
    concurrent requests attempt to create the same version. A savepoint lets
    the losing request recover without rolling back its surrounding work.
    """
    stmt = select(PackageVersion).where(
        PackageVersion.package_id == package_id,
        PackageVersion.version == version,
    )
    result = await session.execute(stmt)
    pkg_version = result.scalar_one_or_none()

    if pkg_version is not None:
        if archive_hash is not None and pkg_version.archive_hash != archive_hash:
            pkg_version.archive_hash = archive_hash
            await session.flush()
        return pkg_version

    pkg_version = PackageVersion(
        package_id=package_id,
        version=version,
        archive_hash=archive_hash,
    )
    try:
        async with session.begin_nested():
            session.add(pkg_version)
            await session.flush()
    except IntegrityError:
        result = await session.execute(stmt)
        pkg_version = result.scalar_one_or_none()
        if pkg_version is None:
            raise

        if archive_hash is not None and pkg_version.archive_hash != archive_hash:
            pkg_version.archive_hash = archive_hash
            await session.flush()

        logger.debug(
            "Reused concurrently created package_version record: id=%s for version=%s",
            pkg_version.id,
            version,
        )
    else:
        logger.debug("Created package_version record: id=%s for version=%s", pkg_version.id, version)

    return pkg_version


async def create_scan(
    session: AsyncSession,
    package_version_id: int,
    scan_id: Optional[UUID] = None,
    status: str = "queued",
) -> Scan:
    """Create a new scan entry in the database."""
    scan = Scan(
        id=scan_id or uuid4(),
        package_version_id=package_version_id,
        status=status,
        created_at=datetime.now(timezone.utc),
    )
    session.add(scan)
    await session.flush()
    logger.info("Created scan %s with status '%s'", scan.id, status)
    return scan


async def update_scan_status(
    session: AsyncSession,
    scan_id: UUID,
    status: str,
) -> Optional[Scan]:
    """Update lifecycle status of a scan."""
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is not None:
        scan.status = status
        await session.flush()
        logger.debug("Scan %s status transitioned to '%s'", scan_id, status)

    return scan


async def save_findings(
    session: AsyncSession,
    scan_id: UUID,
    findings: List[Finding],
) -> List[FindingRecord]:
    """Persist a list of security findings associated with a scan."""
    records: List[FindingRecord] = []
    for f in findings:
        record = FindingRecord(
            scan_id=scan_id,
            rule_id=f.rule_id,
            category=f.category,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            confidence=f.confidence,
            file=f.file,
            line=f.line,
            evidence=f.evidence,
            source=f.source,
            metadata_json=f.metadata,
        )
        session.add(record)
        records.append(record)

    await session.flush()
    logger.debug("Persisted %d findings for scan %s", len(records), scan_id)
    return records


async def save_scan_results(
    session: AsyncSession,
    scan_id: UUID,
    completed_at: Optional[datetime] = None,
    status: str = "completed",
    summary: Optional[str] = None,
    correlations_json: Optional[Any] = None,
    compatibility_profile_json: Optional[Any] = None,
    analyzer_statuses_json: Optional[Any] = None,
    analyzer_errors_json: Optional[Any] = None,
) -> Optional[Scan]:
    """Persist the scan report metadata and completion timestamp."""
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is not None:
        scan.status = status
        scan.completed_at = completed_at or datetime.now(timezone.utc)
        scan.summary = summary
        scan.correlations_json = correlations_json
        scan.compatibility_profile_json = compatibility_profile_json
        scan.analyzer_statuses_json = analyzer_statuses_json
        scan.analyzer_errors_json = analyzer_errors_json

        await session.flush()
        logger.info("Scan %s completed with status '%s'", scan_id, status)

    return scan


async def get_scan(
    session: AsyncSession,
    scan_id: UUID,
) -> Optional[Scan]:
    """Retrieve scan record along with package and package_version relationships."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.package_version).selectinload(PackageVersion.package)
        )
        .where(Scan.id == scan_id)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_scan_with_findings(
    session: AsyncSession,
    scan_id: UUID,
) -> Optional[Scan]:
    """Retrieve scan record along with package, version, and all associated findings."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.package_version).selectinload(PackageVersion.package),
            selectinload(Scan.findings),
        )
        .where(Scan.id == scan_id)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
