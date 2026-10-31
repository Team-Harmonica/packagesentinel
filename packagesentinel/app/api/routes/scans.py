import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import repository
from app.database.connection import get_db_session
from app.schemas.package import PackageInfo, PackageRequest
from app.schemas.scan import ScanResponse, ScanStatus, ScanStatusDetails
from app.workers.scan_worker import dispatch_background_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate asynchronous package security scan",
    description="Accepts a package specification, queues a security scan, and returns a scan job identifier.",
)
async def create_scan_job(
    request: PackageRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    try:
        pkg = await repository.get_or_create_package(
            session=session,
            name=request.name,
            ecosystem=request.ecosystem.value,
        )

        pkg_version = await repository.get_or_create_package_version(
            session=session,
            package_id=pkg.id,
            version=request.version,
        )

        scan = await repository.create_scan(
            session=session,
            package_version_id=pkg_version.id,
            status=ScanStatus.QUEUED.value,
        )

        await session.commit()

        dispatch_background_scan(
            scan_id=scan.id,
            package_req=request,
        )

        return ScanResponse(
            scan_id=scan.id,
            status=ScanStatus.QUEUED,
            message="Package scan queued successfully for background execution",
        )
    except Exception as exc:
        await session.rollback()
        logger.error("Failed to queue scan for %s: %s", request.name, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate scan: {str(exc)}",
        )


@router.get(
    "/{scan_id}",
    response_model=ScanStatusDetails,
    summary="Get scan progress and status",
    description="Polls current status and package details of a scan job.",
)
async def get_scan_status(
    scan_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> ScanStatusDetails:
    scan = await repository.get_scan(session, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )

    pkg_info: PackageInfo | None = None
    if scan.package_version and scan.package_version.package:
        pkg_info = PackageInfo(
            name=scan.package_version.package.name,
            ecosystem=scan.package_version.package.ecosystem,
            version=scan.package_version.version,
            archive_hash=scan.package_version.archive_hash,
        )

    msg = f"Scan is currently in '{scan.status}' state"
    if scan.status == "completed":
        msg = "Scan pipeline completed; review the report for findings and analysis coverage."
    elif scan.status == "failed":
        msg = "Scan execution encountered a failure"

    return ScanStatusDetails(
        scan_id=scan.id,
        status=ScanStatus(scan.status),
        message=msg,
        package=pkg_info,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )
