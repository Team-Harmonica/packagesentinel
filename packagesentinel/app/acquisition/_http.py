"""Minimal HTTPS client for registry calls (stdlib urllib only).

Tests replace ``fetch`` with a fake, so no test touches a live registry.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.acquisition.errors import RegistryError

USER_AGENT = "PkgSentinel/0.1 (static package scanner; +https://github.com/Team-Harmonica/packagesentinel)"
TIMEOUT = 30
MAX_JSON_BYTES = 16 * 1024 * 1024


class NotFound(Exception):
    """HTTP 404 from the registry (callers map it to Package/VersionNotFoundError)."""


def fetch(url: str, limit: int) -> bytes:
    """GET ``url`` over HTTPS and return at most ``limit`` bytes (more -> RegistryError)."""
    if not url.startswith("https://"):
        raise RegistryError(f"refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFound(url) from exc
        raise RegistryError(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RegistryError(f"{url}: {exc}") from exc
    if len(body) > limit:
        raise RegistryError(f"{url}: response larger than {limit} bytes")
    return body


def fetch_json(url: str, limit: int = MAX_JSON_BYTES):
    try:
        return json.loads(fetch(url, limit))
    except ValueError as exc:
        raise RegistryError(f"{url}: invalid JSON") from exc
