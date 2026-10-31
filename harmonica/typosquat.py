"""Typosquat: name is a near-miss of a popular package (and not popular itself).

STUB: owned by Aryan. Replace the body; keep the signature.
"""

from __future__ import annotations

from pathlib import Path

from .scanner import Finding


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    return []
