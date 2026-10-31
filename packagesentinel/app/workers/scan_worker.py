"""Background scan worker managing asynchronous scan execution without external message brokers."""

import asyncio
import logging
from typing import Optional
from uuid import UUID

from app.acquisition.contracts import PackageAcquirer
from app.core.orchestrator import ScanOrchestrator
from app.database.connection import get_sessionmaker
from app.schemas.package import PackageRequest

logger = logging.getLogger(__name__)


async def execute_scan_job(
    scan_id: UUID,
    package_req: PackageRequest,
    orchestrator: Optional[ScanOrchestrator] = None,
    package_acquirer: Optional[PackageAcquirer] = None,
) -> None:
    """Asynchronous worker entrypoint for processing a queued scan job."""
    session_factory = get_sessionmaker()
    orchestrator = orchestrator or ScanOrchestrator(
        package_acquirer=package_acquirer,
    )

    async with session_factory() as session:
        try:
            logger.info("Worker starting scan job for scan_id=%s", scan_id)
            await orchestrator.execute_scan(
                session=session,
                scan_id=scan_id,
                package_req=package_req,
            )
            logger.info("Worker finished scan job for scan_id=%s", scan_id)
        except Exception as exc:
            logger.error("Scan job %s failed during execution: %s", scan_id, exc, exc_info=True)


def dispatch_background_scan(
    scan_id: UUID,
    package_req: PackageRequest,
    orchestrator: Optional[ScanOrchestrator] = None,
    package_acquirer: Optional[PackageAcquirer] = None,
) -> asyncio.Task:
    """Dispatch the scan job to Python asyncio event loop background tasks."""
    task = asyncio.create_task(
        execute_scan_job(scan_id, package_req, orchestrator, package_acquirer)
    )
    logger.debug("Dispatched background asyncio task %s for scan %s", task.get_name(), scan_id)
    return task
