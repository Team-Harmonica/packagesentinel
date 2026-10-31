"""Scoring + verdict assembly.

PLACEHOLDER (build order step 4): plain capped sum of weights. The real
version adds combination rules (weak signals together = strong signal) and
the "popular package near a popular name" false-alarm guard.
"""

from __future__ import annotations

from .profile import build_profile
from .scanner import Finding

MALICIOUS_AT = 60
SUSPICIOUS_AT = 25


def score(findings: list[Finding]) -> tuple[int, str]:
    total = min(100, sum(max(0, f.weight) for f in findings))
    if total >= MALICIOUS_AT or any(f.severity == "malicious" for f in findings):
        band = "malicious"
    elif total >= SUSPICIOUS_AT:
        band = "suspicious"
    else:
        band = "safe"
    return total, band


def build_verdict(pkg: str | dict, findings: list[Finding]) -> dict:
    """`pkg` is the package name, or the meta dict from resolve()."""
    meta = pkg if isinstance(pkg, dict) else {"name": pkg}
    total, band = score(findings)
    capabilities, mismatches = build_profile(findings, meta)
    order = {"malicious": 0, "suspicious": 1, "info": 2}
    ranked = sorted(findings, key=lambda f: (order[f.severity], -f.weight))
    return {
        "package": meta.get("name", ""),
        "version": meta.get("version", ""),
        "score": total,
        "band": band,
        "findings": [f.to_dict() for f in ranked],
        "capabilities": capabilities,
        "mismatches": mismatches,
    }
