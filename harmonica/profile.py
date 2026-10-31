"""Capability profile: bucket findings into filesystem / network / process /
env and flag mismatches against the package's stated purpose.
STUB (build order step 5).
"""

from __future__ import annotations

from .scanner import Finding


def build_profile(findings: list[Finding], meta: dict | None = None) -> tuple[dict, list]:
    """Return (capabilities, mismatches)."""
    return {}, []
