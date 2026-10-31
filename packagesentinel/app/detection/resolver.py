"""Turn whatever the user gave us into (pkg_dir, meta) for run_scanner.

    resolve("./some-unpacked-dir")            local folder (no network)
    resolve("./left-pad-1.3.0.tgz")           local archive, safely extracted
    resolve("left-pad", "npm", "1.3.0")       registry fetch, exact version
    resolve("requests", "pypi")               registry fetch, latest
    extract_upload(file_bytes)                uploaded archive (the web demo path)

Everything is static: archives are extracted by app.acquisition.archive
(zip-slip / bomb guarded) and nothing is ever executed. Acquisition modules
are stdlib only and imported lazily, so the scanner stays zero-dependency.

Registry and archive results own a temp directory; pass the returned meta to
cleanup() when done (no-op for local folders).
"""

from __future__ import annotations

from pathlib import Path


def _empty_meta(name: str, ecosystem: str) -> dict:
    from app.acquisition.archive import empty_meta
    return empty_meta(name, ecosystem)


def resolve(pkg: str, ecosystem: str = "npm", version: str | None = None,
            dest: str | Path | None = None) -> tuple[Path, dict]:
    from app.acquisition import archive

    path = Path(pkg)
    if version is None and path.is_dir():
        meta = archive.read_metadata(path, path, ecosystem)  # data only, never executed
        meta["ecosystem"] = meta["ecosystem"] or ecosystem
        if not meta["name"] or meta["name"] == path.name:
            meta["name"] = meta["name"] or path.resolve().name
        return path, meta
    if version is None and path.is_file():
        return archive.extract_with_meta(path.read_bytes(), dest, ecosystem, "local-archive")
    return resolve_registry(pkg, ecosystem, version, dest)


def resolve_registry(pkg: str, ecosystem: str = "npm", version: str | None = None,
                     dest: str | Path | None = None) -> tuple[Path, dict]:
    """Registry fetch only: never treats `pkg` as a local path. Use this for
    names that come from the network (the web server), so a request can't
    point the scanner at files on the host."""
    if ecosystem == "npm":
        from app.acquisition.npm import fetch_npm
        return fetch_npm(pkg, version, dest)
    if ecosystem == "pypi":
        from app.acquisition.pypi import fetch_pypi
        return fetch_pypi(pkg, version, dest)
    raise ValueError(f"unsupported ecosystem: {ecosystem!r}")


def extract_upload(file_bytes: bytes, dest: str | Path | None = None,
                   ecosystem: str | None = None) -> tuple[Path, dict]:
    """Uploaded archive bytes -> (pkg_dir, meta). See app.acquisition.archive."""
    from app.acquisition.archive import extract_upload as _extract
    return _extract(file_bytes, dest, ecosystem)


def cleanup(meta: dict) -> None:
    from app.acquisition.archive import cleanup as _cleanup
    _cleanup(meta)
