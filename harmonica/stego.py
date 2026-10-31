"""Image steganography red flags. STUB (build order step 5).

Planned: data after PNG IEND; image-lib + download + exec combo;
abnormally high image entropy. Flag the pattern, don't solve the stego.
"""

from __future__ import annotations

from pathlib import Path

from .scanner import Finding


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    return []
