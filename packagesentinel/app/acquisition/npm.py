"""npm acquisition (stdlib only): exact-version resolve, download, verify, safe extract.

    fetch_npm("left-pad", "1.3.0") -> (pkg_dir, meta)
    NpmAcquirer().acquire(PackageRequest(...)) -> AcquiredPackage   (async contract)
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from urllib.parse import quote

from app.acquisition import _http
from app.acquisition.archive import DEFAULT_LIMITS, Limits, extract_with_meta
from app.acquisition.errors import (
    AcquisitionError,
    ArchiveValidationError,
    PackageNotFoundError,
    RegistryError,
    VersionNotFoundError,
)

REGISTRY = "https://registry.npmjs.org"
DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week"
NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")  # exact version or dist-tag
PACKUMENT_LIMIT = 8 * 1024 * 1024  # only for the optional publish date


def _enc(name: str) -> str:
    return quote(name, safe="@")  # "@scope/pkg" -> "@scope%2Fpkg"


def validate(name: str, version: str | None) -> None:
    if not NAME_RE.match(name or "") or len(name) > 214:
        raise AcquisitionError(f"invalid npm package name: {name!r}")
    if version is not None and not VERSION_RE.match(version):
        raise AcquisitionError(f"invalid npm version: {version!r}")


def resolve_version(name: str, version: str | None = None) -> dict:
    """The registry's document for one exact version ("latest" when None)."""
    validate(name, version)
    tag = version or "latest"
    try:
        doc = _http.fetch_json(f"{REGISTRY}/{_enc(name)}/{quote(tag, safe='')}")
    except _http.NotFound:
        try:
            _http.fetch_json(f"{REGISTRY}/-/package/{_enc(name)}/dist-tags")
        except _http.NotFound:
            raise PackageNotFoundError(f"npm package {name!r} not found") from None
        raise VersionNotFoundError(f"npm package {name!r} has no version {tag!r}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("dist"), dict) or not doc["dist"].get("tarball"):
        raise RegistryError(f"npm registry returned no tarball for {name}@{tag}")
    return doc


def verify(data: bytes, dist: dict) -> str | None:
    """Check the tarball against the registry checksum. Returns a warning or None."""
    integrity = dist.get("integrity") or ""
    for token in integrity.split():
        algo, _, digest = token.partition("-")
        if algo in ("sha512", "sha384", "sha256"):
            actual = base64.b64encode(hashlib.new(algo, data).digest()).decode()
            if actual != digest:
                raise ArchiveValidationError(f"npm tarball {algo} integrity mismatch")
            return None
    if dist.get("shasum"):
        if hashlib.sha1(data).hexdigest() != dist["shasum"].lower():
            raise ArchiveValidationError("npm tarball sha1 shasum mismatch")
        return None
    return "registry provided no checksum for this tarball"


def _best_effort(url: str, limit: int = _http.MAX_JSON_BYTES):
    try:
        return _http.fetch_json(url, limit)
    except (AcquisitionError, _http.NotFound):
        return None


def fetch_npm(name: str, version: str | None = None, dest: str | Path | None = None,
              limits: Limits = DEFAULT_LIMITS) -> tuple[Path, dict]:
    doc = resolve_version(name, version)
    dist = doc["dist"]
    data = _http.fetch(dist["tarball"], limits.max_archive_bytes)
    warning = verify(data, dist)

    pkg_dir, meta = extract_with_meta(data, dest, "npm", "npm-registry", limits)
    exact = str(doc.get("version") or meta["version"])
    meta["name"] = str(doc.get("name") or meta["name"] or name)
    meta["version"] = exact
    meta["ecosystem"] = "npm"
    people = [m.get("name") for m in doc.get("maintainers") or [] if isinstance(m, dict) and m.get("name")]
    meta["maintainers"] = people or meta["maintainers"]
    if isinstance(doc.get("dependencies"), dict):
        meta["dependencies"] = {str(k): str(v) for k, v in doc["dependencies"].items()}
    packument = _best_effort(f"{REGISTRY}/{_enc(name)}", PACKUMENT_LIMIT)
    if isinstance(packument, dict):
        meta["published"] = (packument.get("time") or {}).get(exact)
    downloads = _best_effort(f"{DOWNLOADS_API}/{_enc(name)}")
    if isinstance(downloads, dict) and isinstance(downloads.get("downloads"), int):
        meta["downloads"] = downloads["downloads"]
    if warning:
        meta["acquisition"]["warnings"].append(warning)
    meta["acquisition"]["download_url"] = dist["tarball"]
    return pkg_dir, meta


class NpmAcquirer:
    """PackageAcquirer for npm (async contract from app.acquisition.contracts)."""

    async def acquire(self, request):
        from app.acquisition.acquirer import acquire_with
        return await acquire_with(fetch_npm, request, "npm")
