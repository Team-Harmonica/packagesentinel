"""PkgSentinel demo server: a thin doorway from the frontend to the scanner.

    uvicorn server:app --port 8000          (run from this directory)

    POST /scan        multipart file upload (field "file", optional "ecosystem")
                      -> build_verdict(...) JSON, exactly as the CLI produces it
    POST /scan-name   {"pkg": "left-pad", "ecosystem": "npm", "version": "1.3.0"}
                      -> same verdict JSON (needs network; uploads are the offline path)
    POST /diff        multipart "old" + "new" archives, or
                      {"pkg": "left-pad", "old": "1.3.0", "new": "1.3.1", "ecosystem": "npm"}
                      -> diff JSON (headline, added findings, ...)
    GET  /health      {"ok": true}

No database, no persistence, no background work: every request extracts into
a temp dir, scans statically (nothing is executed), answers, and deletes it.

This is the only file that needs FastAPI + uvicorn. app.detection stays stdlib
only, and multipart bodies are parsed here by hand so there is no
python-multipart dependency.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.acquisition.archive import DEFAULT_LIMITS
from app.acquisition.errors import (
    AcquisitionError,
    PackageNotFoundError,
    RegistryError,
    VersionNotFoundError,
)
from app.detection import diff as diff_mod
from app.detection.resolver import cleanup, extract_upload, resolve_registry
from app.detection.scanner import run_scanner
from app.detection.scoring import build_verdict

ECOSYSTEMS = ("npm", "pypi")
MAX_BODY = 2 * DEFAULT_LIMITS.max_archive_bytes + 64 * 1024  # /diff carries two archives

app = FastAPI(title="PkgSentinel", version="0.1.0", docs_url="/docs", redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# --- errors: always a short JSON message, never a stack trace ----------------


class BadRequest(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _error(status: int, message: str, kind: str) -> JSONResponse:
    return JSONResponse({"error": message, "kind": kind}, status_code=status)


@app.exception_handler(BadRequest)
async def _bad_request(_req: Request, exc: BadRequest):
    return _error(exc.status, str(exc), "BadRequest")


@app.exception_handler(AcquisitionError)
async def _acquisition(_req: Request, exc: AcquisitionError):
    # ExtractionError / ArchiveValidationError (zip-slip, bombs, corrupt) -> 400
    status = 400
    if isinstance(exc, (PackageNotFoundError, VersionNotFoundError)):
        status = 404
    elif isinstance(exc, RegistryError):
        status = 502
    return _error(status, str(exc), type(exc).__name__)


@app.exception_handler(Exception)
async def _unexpected(_req: Request, exc: Exception):
    return _error(500, f"scan failed: {type(exc).__name__}", "InternalError")


# --- request parsing (stdlib only) -------------------------------------------


async def _body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY:
        raise BadRequest(f"upload too large (limit {MAX_BODY // (1024 * 1024)} MB)", 413)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            raise BadRequest(f"upload too large (limit {MAX_BODY // (1024 * 1024)} MB)", 413)
        chunks.append(chunk)
    return b"".join(chunks)


def parse_multipart(body: bytes, content_type: str) -> dict[str, tuple[str | None, bytes]]:
    """{field name: (filename or None, raw bytes)} from a multipart/form-data body."""
    m = re.search(r'boundary="?([^";]+)"?', content_type)
    if not m:
        raise BadRequest("multipart body without a boundary")
    delimiter = b"--" + m.group(1).encode("latin-1")
    fields: dict[str, tuple[str | None, bytes]] = {}
    for part in body.split(delimiter)[1:]:
        if part.startswith(b"--"):
            break  # closing delimiter
        head, sep, content = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        if content.endswith(b"\r\n"):
            content = content[:-2]
        headers = head.decode("utf-8", "replace")
        name = re.search(r'\bname="([^"]*)"', headers)
        if not name:
            continue
        filename = re.search(r'\bfilename="([^"]*)"', headers)
        fields[name.group(1)] = (filename.group(1) if filename else None, content)
    return fields


async def _form_or_json(request: Request) -> tuple[str, dict]:
    content_type = request.headers.get("content-type", "")
    body = await _body(request)
    if content_type.startswith("multipart/form-data"):
        return "form", parse_multipart(body, content_type)
    if content_type.startswith("application/json") or body.lstrip().startswith(b"{"):
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            raise BadRequest("request body is not valid JSON") from None
        if not isinstance(data, dict):
            raise BadRequest("JSON body must be an object")
        return "json", data
    raise BadRequest("send multipart/form-data (file upload) or application/json")


def _ecosystem(value) -> str | None:
    if value in (None, ""):
        return None
    value = value.decode() if isinstance(value, bytes) else str(value)
    if value.strip().lower() not in ECOSYSTEMS:
        raise BadRequest(f"ecosystem must be one of {', '.join(ECOSYSTEMS)}")
    return value.strip().lower()


def _text(data: dict, key: str, required: bool = True) -> str | None:
    value = data.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise BadRequest(f"missing field: {key!r}")
        return None
    if not isinstance(value, str):
        raise BadRequest(f"field {key!r} must be a string")
    return value.strip()


def _file(fields: dict, key: str) -> bytes:
    if key not in fields or not fields[key][1]:
        raise BadRequest(f"missing uploaded file field {key!r}")
    return fields[key][1]


# --- scanning (sync, run in a worker thread) ---------------------------------


def _verdict(pkg_dir: Path, meta: dict) -> dict:
    try:
        return build_verdict(meta, run_scanner(pkg_dir, meta))
    finally:
        cleanup(meta)


def _scan_upload(data: bytes, ecosystem: str | None) -> dict:
    return _verdict(*extract_upload(data, ecosystem=ecosystem))


def _scan_name(pkg: str, ecosystem: str, version: str | None) -> dict:
    return _verdict(*resolve_registry(pkg, ecosystem, version))


def _diff_uploads(old: bytes, new: bytes, ecosystem: str | None) -> dict:
    old_dir, old_meta = extract_upload(old, ecosystem=ecosystem)
    try:
        new_dir, new_meta = extract_upload(new, ecosystem=ecosystem)
        try:
            return diff_mod.compare(old_dir, old_meta, new_dir, new_meta)
        finally:
            cleanup(new_meta)
    finally:
        cleanup(old_meta)


def _diff_versions(pkg: str, old: str, new: str, ecosystem: str) -> dict:
    old_dir, old_meta = resolve_registry(pkg, ecosystem, old)
    try:
        new_dir, new_meta = resolve_registry(pkg, ecosystem, new)
        try:
            return diff_mod.compare(old_dir, old_meta, new_dir, new_meta)
        finally:
            cleanup(new_meta)
    finally:
        cleanup(old_meta)


# --- routes --------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/scan")
async def scan(request: Request):
    kind, fields = await _form_or_json(request)
    if kind != "form":
        raise BadRequest("POST /scan takes a multipart file upload (field 'file'); use /scan-name for names")
    data = fields["file"][1] if "file" in fields else next(
        (content for filename, content in fields.values() if filename is not None), b"")
    if not data:
        raise BadRequest("no file uploaded (multipart field 'file')")
    ecosystem = _ecosystem(fields.get("ecosystem", (None, None))[1])
    return await run_in_threadpool(_scan_upload, data, ecosystem)


@app.post("/scan-name")
async def scan_name(request: Request):
    kind, data = await _form_or_json(request)
    if kind != "json":
        raise BadRequest("POST /scan-name takes JSON: {\"pkg\", \"ecosystem\", \"version\"}")
    pkg = _text(data, "pkg")
    ecosystem = _ecosystem(data.get("ecosystem")) or "npm"
    version = _text(data, "version", required=False)
    return await run_in_threadpool(_scan_name, pkg, ecosystem, version)


@app.post("/diff")
async def diff(request: Request):
    kind, data = await _form_or_json(request)
    if kind == "form":
        ecosystem = _ecosystem(data.get("ecosystem", (None, None))[1])
        return await run_in_threadpool(_diff_uploads, _file(data, "old"), _file(data, "new"), ecosystem)
    pkg = _text(data, "pkg")
    old, new = _text(data, "old"), _text(data, "new")
    ecosystem = _ecosystem(data.get("ecosystem")) or "npm"
    return await run_in_threadpool(_diff_versions, pkg, old, new, ecosystem)
