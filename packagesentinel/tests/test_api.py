"""Tests for FastAPI HTTP routes and frontend API integration."""

import asyncio
from uuid import uuid4
import pytest
from httpx import AsyncClient

from app.database import repository
from app.database.connection import get_sessionmaker
from app.schemas.package import Ecosystem, PackageRequest


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: AsyncClient):
    """Verify GET /api/v1/health returns 200 and healthy database status."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert "PackageSentinel" in data["app"]


@pytest.mark.asyncio
async def test_create_scan_endpoint_and_progress(async_client: AsyncClient):
    """Verify POST /api/v1/scans queues a scan and returns 202 with scan_id."""
    payload = {
        "ecosystem": "npm",
        "name": "clean-express-app",
        "version": "1.0.0",
    }
    response = await async_client.post("/api/v1/scans", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "queued"
    assert "queued" in data["message"].lower()

    scan_id = data["scan_id"]

    # Poll status endpoint
    status_resp = await async_client.get(f"/api/v1/scans/{scan_id}")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["scan_id"] == scan_id
    assert status_data["status"] in ("queued", "fetching", "analyzing", "completed")


@pytest.mark.asyncio
async def test_scan_not_found(async_client: AsyncClient):
    """Verify 404 for nonexistent scan ID."""
    fake_id = uuid4()
    resp = await async_client.get(f"/api/v1/scans/{fake_id}")
    assert resp.status_code == 404

    report_resp = await async_client.get(f"/api/v1/scans/{fake_id}/report")
    assert report_resp.status_code == 404


@pytest.mark.asyncio
async def test_get_report_when_scan_in_progress(async_client: AsyncClient, test_engine):
    """Verify 409 Conflict when attempting to retrieve report of an uncompleted scan."""
    session_factory = get_sessionmaker()
    async with session_factory() as session:
        pkg = await repository.get_or_create_package(session, "running-pkg", "pypi")
        version = await repository.get_or_create_package_version(session, pkg.id, "0.1.0")
        scan = await repository.create_scan(session, version.id, status="analyzing")
        await session.commit()
        scan_id = scan.id

    report_resp = await async_client.get(f"/api/v1/scans/{scan_id}/report")
    assert report_resp.status_code == 409
    assert "in progress" in report_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_end_to_end_api_submission_and_report_retrieval(async_client: AsyncClient):
    """Full API integration test: Submit scan, await background completion, and fetch report."""
    payload = {
        "ecosystem": "npm",
        "name": "suspicious-sample-tool",
        "version": "1.0.0",
    }
    submit_resp = await async_client.post("/api/v1/scans", json=payload)
    assert submit_resp.status_code == 202
    scan_id = submit_resp.json()["scan_id"]

    # Wait for the background asyncio task to complete (should be nearly instantaneous)
    for _ in range(20):
        status_resp = await async_client.get(f"/api/v1/scans/{scan_id}")
        assert status_resp.status_code == 200
        if status_resp.json()["status"] == "completed":
            break
        await asyncio.sleep(0.1)

    # Retrieve final report
    report_resp = await async_client.get(f"/api/v1/scans/{scan_id}/report")
    assert report_resp.status_code == 200
    report = report_resp.json()

    assert report["scan_id"] == scan_id
    assert report["package"]["name"] == "suspicious-sample-tool"
    assert report["package"]["ecosystem"] == "npm"
    assert report["analysis_complete"] is False
    assert report["findings"] == []
    assert report["correlations"] == []
    assert "compatibility_profile" in report
    assert report["compatibility_profile"]["coverage"] == 0.0
    assert "incomplete" in report["summary"].lower()
    assert "package contents" in report["analyzer_errors"]["static_analysis"].lower()
    assert "verdict" not in report
    assert "risk_score" not in report
