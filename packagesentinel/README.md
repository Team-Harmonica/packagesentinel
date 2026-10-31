# PackageSentinel

PackageSentinel is a FastAPI backend for scanning npm and PyPI packages. It
provides scan endpoints, persistence, asynchronous orchestration, compatibility
profiles, evidence aggregation, correlation, and report generation.

Persistence uses async SQLite via `aiosqlite`; the default database is
`./packagesentinel.db`. Configure its location with `DATABASE_URL` using the
`sqlite+aiosqlite` driver. The backend has no external database or object
storage requirement.

Static detectors are under `app/detection/`. `PackageContentAnalyzer.analyze_directory()`
scans acquired packages for suspicious code, invisible-Unicode payloads, and
steganographic content in images. npm and PyPI acquisition uses exact-version
registry requests and safe archive extraction. The scanner reads package files
as data and does not execute them. Reports record acquisition failures and mark
static analysis as skipped rather than implying that a package is safe. Reports
track static, metadata, typosquatting, behavioral, and dependency analysis
separately. Coverage counts completed applicable stages; unavailable or skipped
stages reduce coverage. A scan job can complete while `analysis_complete` is
false when one or more applicable stages did not complete.

The scanner includes an offline typosquatting signal for names one edit or
adjacent transposition away from a curated set of popular npm/PyPI packages,
and for names using common confusable characters. It requires the requested
package's `name` and `ecosystem` in scanner metadata; the reference list is
intentionally finite and is not a registry-wide typosquatting service. The API
runs this name-only check from the scan request without downloaded package
contents. Hook and broader metadata checks are not implemented.
The API report exposes `detection_flags.metadata` and
`detection_flags.typosquatting` alongside the findings. The metadata analyzer
adapter invokes `app.detection.metadata.check(package_dir, metadata)` and
normalizes its findings into the shared report schema. The local CLI includes scoring,
evaluation, calibration, and
directory-diff tools; score/verdict output is not part of the API report
contract. The CLI's capability-profile builder remains a stub, so its
capability and mismatch summaries are currently empty.

## Setup

```bash
cd packagesentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

The API documentation is available at `http://127.0.0.1:8000/docs`.

## API

- `POST /api/v1/scans` — queue a scan using ecosystem, name, and version.
- `GET /api/v1/scans/{scan_id}` — get scan progress.
- `GET /api/v1/scans/{scan_id}/report` — get findings, correlations, analysis
  coverage, and analyzer availability details.
- `GET /api/v1/health` — check API and database connectivity.

## Local static detector use

The synchronous detector helper accepts an unpacked directory:

```python
from app.detection.analyzers import PackageContentAnalyzer

findings = PackageContentAnalyzer.analyze_directory("/path/to/unpacked/package")
```

Package files are read as data; the scanner does not execute package code.

The local analysis CLI is also available as `packagesentinel check <directory>`,
`packagesentinel reveal <directory>`, `packagesentinel diff <old> <new>`,
`packagesentinel eval`, and `packagesentinel calibrate`. The CLI accepts local
directories; unlike API scan jobs, it does not fetch packages from npm or PyPI.

## Acquisition contract

Acquisition implementations share `app.acquisition.contracts`. An
`AcquiredPackage` identifies the requested package and version, its extracted
directory, the original archive's SHA-256, normalized registry metadata,
non-fatal warnings, and structured `SkippedFile` entries. The metadata is a
registry-independent dictionary; acquisition implementations should normalize
registry responses before returning it.

The scan orchestrator chooses the npm or PyPI acquirer from the request and
applies a 120-second acquisition timeout. It passes the resulting artifact to
configured analyzers, persists the archive SHA-256 on the package version, and
calls `artifact.cleanup()` in a `finally` block after analysis. The acquirer
creates and initially owns a `TemporaryDirectory`, then transfers its handle
with the returned artifact. The extracted directory must be inside that
temporary directory.
Acquisition failures raise `AcquisitionError` or one of its specific
subclasses: `PackageNotFoundError`, `VersionNotFoundError`, `RegistryError`,
`ArchiveValidationError`, or `ExtractionError`. Failures and timeouts are
recorded in the report's `acquisition` analyzer status; static analysis is
skipped and the report remains incomplete rather than implying a safe result.

## Tests

```bash
pytest
```
