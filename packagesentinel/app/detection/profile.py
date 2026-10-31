"""Capability-profile extension point used by the local scoring CLI.

Capability buckets and purpose mismatches are not implemented yet.
"""

from __future__ import annotations

from .scanner import Finding


def build_profile(findings: list[Finding], meta: dict | None = None) -> tuple[dict, list]:
    """Return (capabilities, mismatches)."""
    return {}, []
