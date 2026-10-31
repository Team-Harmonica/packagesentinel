"""Metadata red flags: brand-new, few downloads, maintainer change, no repo.

STUB: owned by Aryan. Replace the body; keep the signature.
"""

from __future__ import annotations

from pathlib import Path

from .scanner import Finding


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    return []
