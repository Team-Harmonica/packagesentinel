"""Read package metadata from a local, already-unpacked directory.

Registry acquisition and archive extraction are provided by the acquisition
service, not this local CLI helper.
"""

from __future__ import annotations

import json
from pathlib import Path


def _empty_meta(name: str, ecosystem: str) -> dict:
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": "",
        "published": None,
        "downloads": None,
        "maintainers": [],
        "repo_url": None,
        "dependencies": {},
    }


def resolve(pkg: str, ecosystem: str = "npm") -> tuple[Path, dict]:
    path = Path(pkg)
    if not path.is_dir():
        raise NotImplementedError(
            f"{pkg!r}: registry fetch / tarballs not wired yet; pass an unpacked directory"
        )

    meta = _empty_meta(path.resolve().name, ecosystem)
    manifest = path / "package.json"
    if manifest.is_file():  # parsed as data only, never executed
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            meta["name"] = data.get("name") or meta["name"]
            meta["version"] = data.get("version") or ""
            meta["dependencies"] = data.get("dependencies") or {}
        except (ValueError, OSError):
            pass
    return path, meta
