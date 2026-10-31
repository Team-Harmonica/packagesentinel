"""PyPI acquisition (stdlib only): exact-version resolve, download, verify, safe extract.

    fetch_pypi("requests", "2.32.3") -> (pkg_dir, meta)
    PyPIAcquirer().acquire(PackageRequest(...)) -> AcquiredPackage   (async contract)

The sdist is preferred over wheels: it contains setup.py, i.e. the code that
runs at install time, which is exactly what we want to inspect.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import quote

from app.acquisition import _http
from app.acquisition.archive import DEFAULT_LIMITS, Limits, _clean_url, _REQ_NAME, extract_with_meta
from app.acquisition.errors import (
    AcquisitionError,
    ArchiveValidationError,
    PackageNotFoundError,
    RegistryError,
    VersionNotFoundError,
)

JSON_API = "https://pypi.org/pypi"
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
SDIST_SUFFIXES = (".tar.gz", ".tgz", ".zip")


def validate(name: str, version: str | None) -> None:
    if not NAME_RE.match(name or "") or len(name) > 200:
        raise AcquisitionError(f"invalid PyPI project name: {name!r}")
    if version is not None and not VERSION_RE.match(version):
        raise AcquisitionError(f"invalid PyPI version: {version!r}")


def resolve_release(name: str, version: str | None = None) -> dict:
    validate(name, version)
    url = f"{JSON_API}/{quote(name)}/{quote(version)}/json" if version else f"{JSON_API}/{quote(name)}/json"
    try:
        doc = _http.fetch_json(url)
    except _http.NotFound:
        if version:
            try:
                _http.fetch_json(f"{JSON_API}/{quote(name)}/json")
            except _http.NotFound:
                raise PackageNotFoundError(f"PyPI project {name!r} not found") from None
            raise VersionNotFoundError(f"PyPI project {name!r} has no version {version!r}") from None
        raise PackageNotFoundError(f"PyPI project {name!r} not found") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("info"), dict):
        raise RegistryError(f"PyPI returned an unusable document for {name}")
    return doc


def pick_file(files: list[dict]) -> dict:
    usable = [f for f in files if isinstance(f, dict) and f.get("url") and not f.get("yanked")] or \
             [f for f in files if isinstance(f, dict) and f.get("url")]
    sdists = [f for f in usable if f.get("packagetype") == "sdist" and f.get("filename", "").endswith(SDIST_SUFFIXES)]
    wheels = [f for f in usable if f.get("packagetype") == "bdist_wheel"]
    wheels.sort(key=lambda f: ("none-any" not in f.get("filename", ""), f.get("filename", "")))
    choice = (sdists or wheels or [None])[0]
    if choice is None:
        raise VersionNotFoundError("release has no downloadable sdist or wheel")
    return choice


def fetch_pypi(name: str, version: str | None = None, dest: str | Path | None = None,
               limits: Limits = DEFAULT_LIMITS) -> tuple[Path, dict]:
    doc = resolve_release(name, version)
    info = doc["info"]
    file = pick_file(doc.get("urls") or [])
    data = _http.fetch(file["url"], limits.max_archive_bytes)
    expected = (file.get("digests") or {}).get("sha256")
    warnings = []
    if expected:
        if hashlib.sha256(data).hexdigest() != expected.lower():
            raise ArchiveValidationError(f"PyPI file {file.get('filename')} sha256 mismatch")
    else:
        warnings.append("PyPI provided no sha256 digest for this file")

    pkg_dir, meta = extract_with_meta(data, dest, "pypi", "pypi-registry", limits)
    meta["ecosystem"] = "pypi"
    meta["name"] = str(info.get("name") or meta["name"] or name)
    meta["version"] = str(info.get("version") or meta["version"])
    meta["published"] = file.get("upload_time_iso_8601") or file.get("upload_time")
    meta["downloads"] = None  # PyPI's JSON API no longer reports download counts
    people = [info.get("maintainer"), info.get("author")]
    meta["maintainers"] = list(dict.fromkeys(p for p in people if p)) or meta["maintainers"]
    urls = {str(k).lower(): v for k, v in (info.get("project_urls") or {}).items()}
    repo = next((urls[k] for k in urls if any(w in k for w in ("source", "repository", "code", "github"))), None)
    meta["repo_url"] = _clean_url(repo or urls.get("homepage") or info.get("home_page")) or meta["repo_url"]
    if not meta["dependencies"] and info.get("requires_dist"):
        deps = {}
        for req in info["requires_dist"]:
            m = _REQ_NAME.match(req)
            if m:
                deps[m.group(1)] = m.group(2).strip()
        meta["dependencies"] = deps
    if info.get("summary"):
        meta.setdefault("description", info["summary"])
    meta["acquisition"]["warnings"] += warnings
    meta["acquisition"]["download_url"] = file["url"]
    meta["acquisition"]["filename"] = file.get("filename")
    return pkg_dir, meta


class PyPIAcquirer:
    """PackageAcquirer for PyPI (async contract from app.acquisition.contracts)."""

    async def acquire(self, request):
        from app.acquisition.acquirer import acquire_with
        return await acquire_with(fetch_pypi, request, "pypi")
