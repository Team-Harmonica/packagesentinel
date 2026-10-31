# PackageSentinel

PackageSentinel is a FastAPI backend for scanning npm and PyPI packages. It
provides scan endpoints, persistence, asynchronous orchestration, compatibility
profiles, evidence aggregation, correlation, and report generation.

Persistence uses async SQLite via `aiosqlite`; the default database is
`./packagesentinel.db`. Configure its location with `DATABASE_URL` using the
`sqlite+aiosqlite` driver. The backend has no external database or object
storage requirement.

Static detectors are under `app/detection/`. `PackageContentAnalyzer.analyze_directory()`
can scan an already-unpacked package for suspicious code, invisible-Unicode
payloads, and steganographic content in images. The scanner reads package files
as data and does not execute them. Registry download/archive acquisition is not
wired into the API yet, so API scan reports mark static analysis unavailable
and report incomplete coverage rather than implying that a package is safe.

Hook, metadata, and typosquatting checks are not yet implemented and are not
registered as active checks.
Typosquat and metadata flags from a frontend remain deferred until that
frontend request contract is available. The local CLI includes scoring,
evaluation, calibration, and directory-diff tools; score/verdict output is not
part of the API report contract. The CLI's capability-profile builder remains
a stub, so its capability and mismatch summaries are currently empty.

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

## Static detector use

The current detector interface accepts an unpacked directory:

```python
from app.detection.analyzers import PackageContentAnalyzer

findings = PackageContentAnalyzer.analyze_directory("/path/to/unpacked/package")
```

Package files are read as data; the scanner does not execute package code.

The local analysis CLI is also available as `packagesentinel check <directory>`,
`packagesentinel reveal <directory>`, `packagesentinel diff <old> <new>`,
`packagesentinel eval`, and `packagesentinel calibrate`. The CLI accepts local
directories; it does not fetch packages from npm or PyPI.

## Acquisition contract

Acquisition implementations share `app.acquisition.contracts`. An
`AcquiredPackage` identifies the requested package and version, its extracted
directory, the original archive's SHA-256, normalized registry metadata,
non-fatal warnings, and structured `SkippedFile` entries. The metadata is a
registry-independent dictionary; acquisition implementations should normalize
registry responses before returning it.

The acquirer creates and initially owns a `TemporaryDirectory`, then transfers
its handle with the returned artifact. The caller owns cleanup after receiving
the artifact and must call `artifact.cleanup()` in a `finally` block after
analysis. The extracted directory must be inside that temporary directory.
Acquisition failures raise `AcquisitionError` or one of its specific
subclasses: `PackageNotFoundError`, `VersionNotFoundError`, `RegistryError`,
`ArchiveValidationError`, or `ExtractionError`; failures must not be returned
as incomplete artifacts.

## Tests

```bash
pytest
```
