"""Install hooks: npm pre/post-install scripts, setup.py code execution.

STUB: owned by Aryan. Replace the body; keep the signature.
"""

from __future__ import annotations

from pathlib import Path

from .scanner import Finding


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    return []
