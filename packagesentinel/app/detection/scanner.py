"""Scanner spine for static analysis of unpacked package directories.

Every check is a function ``check(pkg_dir: Path, meta: dict) -> list[Finding]``.
run_scanner() calls the integrated checks in order and concatenates the
results. A check that raises never kills the scan; the failure is recorded as
an ``info`` Finding so it remains visible in the report.

Nothing here (or in any check) executes package code. Files are read as bytes.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterator

SEVERITIES = ("info", "suspicious", "malicious")


@dataclass
class Finding:
    check: str
    severity: str  # info | suspicious | malicious
    weight: int
    message: str
    location: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")

    def to_dict(self) -> dict:
        return asdict(self)


Check = Callable[[Path, dict], "list[Finding]"]

# --- shared file walking ----------------------------------------------------

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__"}
MAX_FILE_BYTES = 20 * 1024 * 1024  # minified bundles can be big; tarball bombs bigger


def iter_files(pkg_dir: Path | str) -> Iterator[Path]:
    """Yield every regular file under pkg_dir, deterministically ordered.

    Symlinks are never followed: a malicious tarball could otherwise point the
    scanner at ~/.ssh or /etc and make us "find" things outside the package.
    """
    root = Path(pkg_dir)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def rel(path: Path, pkg_dir: Path | str) -> str:
    """Package-relative POSIX path, used in Finding.location."""
    return Path(path).relative_to(pkg_dir).as_posix()


# --- orchestration ----------------------------------------------------------


def _check_groups() -> list[tuple[str, list[tuple[str, Check]]]]:
    # Imported here so check modules can import Finding from this module
    # without a circular import.
    from . import code_scan, glassworm

    return [
        ("raw", [("glassworm", glassworm.check)]),
        ("code", [("code_scan", code_scan.check)]),
    ]


def run_scanner(pkg_dir: Path | str, meta: dict | None = None) -> list[Finding]:
    pkg_dir = Path(pkg_dir)
    if not pkg_dir.is_dir():
        raise NotADirectoryError(f"not an unpacked package directory: {pkg_dir}")
    meta = meta or {}

    findings: list[Finding] = []
    for _group, checks in _check_groups():
        for name, check in checks:
            try:
                findings.extend(check(pkg_dir, meta))
            except Exception as exc:  # one broken check must not sink the scan
                findings.append(Finding(
                    check=name,
                    severity="info",
                    weight=0,
                    message=f"check failed to run: {type(exc).__name__}: {exc}",
                ))
    return findings
