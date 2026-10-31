"""Build archives in memory and fake the npm / PyPI registries (no network)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from app.acquisition import _http


def make_tgz(files: dict[str, bytes | str], links: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755  # extraction must NOT keep the exec bit
            tf.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


def make_zip(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def tgz_from_dir(path: Path, prefix: str = "package/") -> bytes:
    return make_tgz({prefix + p.relative_to(path).as_posix(): p.read_bytes()
                     for p in sorted(path.rglob("*")) if p.is_file()})


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class FakeRegistry:
    """url -> bytes | dict | list. Anything not listed is a 404."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.requested: list[str] = []

    def fetch(self, url: str, limit: int) -> bytes:
        self.requested.append(url)
        if url not in self.routes:
            raise _http.NotFound(url)
        body = self.routes[url]
        return body if isinstance(body, bytes) else json.dumps(body).encode()

    def fetch_json(self, url: str, limit: int = _http.MAX_JSON_BYTES):
        return json.loads(self.fetch(url, limit))

    @contextmanager
    def active(self):
        with mock.patch.object(_http, "fetch", self.fetch), mock.patch.object(_http, "fetch_json", self.fetch_json):
            yield self


def npm_routes(name: str, versions: dict[str, bytes], downloads: int = 1234) -> dict:
    """Registry routes for an npm package with the given {version: tarball}."""
    base = "https://registry.npmjs.org"
    routes: dict = {
        f"{base}/-/package/{name}/dist-tags": {"latest": max(versions)},
        f"{base}/{name}": {"name": name, "time": {v: f"2026-10-0{i + 1}T00:00:00.000Z"
                                                    for i, v in enumerate(sorted(versions))}},
        f"https://api.npmjs.org/downloads/point/last-week/{name}": {"downloads": downloads, "package": name},
    }
    for v, tgz in versions.items():
        url = f"{base}/{name}/-/{name}-{v}.tgz"
        manifest = json.loads(tarfile.open(fileobj=io.BytesIO(tgz)).extractfile("package/package.json").read())
        doc = {**manifest, "name": name, "version": v, "maintainers": [{"name": "alice"}],
               "dist": {"tarball": url, "integrity": sri(tgz), "shasum": hashlib.sha1(tgz).hexdigest()}}
        routes[f"{base}/{name}/{v}"] = doc
        routes[url] = tgz
    routes[f"{base}/{name}/latest"] = routes[f"{base}/{name}/{max(versions)}"]
    return routes
