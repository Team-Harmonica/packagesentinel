"""Offline package-name typo detection against curated popular package names."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from .scanner import Finding

POPULAR_PACKAGES = {
    "npm": frozenset({
        "@babel/core",
        "@types/node",
        "axios",
        "chalk",
        "commander",
        "debug",
        "dotenv",
        "express",
        "fast-glob",
        "glob",
        "inquirer",
        "jest",
        "jquery",
        "lodash",
        "minimist",
        "moment",
        "next",
        "node-fetch",
        "nodemon",
        "open",
        "picomatch",
        "prettier",
        "react",
        "react-dom",
        "request",
        "rimraf",
        "semver",
        "serve",
        "socket.io",
        "typescript",
        "vite",
        "webpack",
        "yargs",
    }),
    "pypi": frozenset({
        "aiohttp",
        "beautifulsoup4",
        "boto3",
        "django",
        "fastapi",
        "flask",
        "httpx",
        "jinja2",
        "matplotlib",
        "numpy",
        "pandas",
        "pillow",
        "pip",
        "pydantic",
        "pytest",
        "pyyaml",
        "requests",
        "scikit-learn",
        "scipy",
        "setuptools",
        "sqlalchemy",
        "torch",
        "urllib3",
    }),
}

_CONFUSABLES = str.maketrans({
    "\u0430": "a",  # Cyrillic
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0455": "s",
    "\u0456": "i",
    "\u04cf": "l",
    "\u0443": "y",
    "\u03b1": "a",  # Greek
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c5": "u",
    "\u03c7": "x",
})


def _normalize(name: str, ecosystem: str) -> str:
    normalized = unicodedata.normalize("NFKC", name).casefold()
    if ecosystem == "pypi":
        normalized = re.sub(r"[-_.]+", "-", normalized)
    return normalized


def _skeleton(name: str, ecosystem: str) -> str:
    return _normalize(name, ecosystem).translate(_CONFUSABLES)


def _one_edit_apart(left: str, right: str) -> bool:
    """Return whether two distinct names differ by one insertion, deletion,
    replacement, or adjacent transposition.
    """
    if left == right or abs(len(left) - len(right)) > 1:
        return False

    if len(left) == len(right):
        mismatches = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        if len(mismatches) == 1:
            return True
        return (
            len(mismatches) == 2
            and mismatches[1] == mismatches[0] + 1
            and left[mismatches[0]] == right[mismatches[1]]
            and left[mismatches[1]] == right[mismatches[0]]
        )

    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    i = j = 0
    skipped = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def _candidate(meta: dict) -> tuple[str, str] | None:
    ecosystem_value = meta.get("ecosystem")
    ecosystem = getattr(ecosystem_value, "value", ecosystem_value)
    if not isinstance(ecosystem, str) or ecosystem not in POPULAR_PACKAGES:
        return None

    name = meta.get("package_name") or meta.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    return ecosystem, name.strip()


def check(_pkg_dir: Path, meta: dict) -> list[Finding]:
    """Find a package name one edit away from a popular package in its ecosystem.

    ``meta`` must identify the requested package with ``name`` or
    ``package_name`` and its ecosystem (``npm`` or ``pypi``).
    """
    candidate = _candidate(meta)
    if candidate is None:
        return []

    ecosystem, original_name = candidate
    normalized_name = _normalize(original_name, ecosystem)
    skeleton = _skeleton(original_name, ecosystem)
    if len(normalized_name) < 4:
        return []

    matches = []
    confusable_matches = []
    for name in POPULAR_PACKAGES[ecosystem]:
        reference = _normalize(name, ecosystem)
        if normalized_name == reference:
            continue
        reference_skeleton = _skeleton(name, ecosystem)
        if skeleton == reference_skeleton:
            confusable_matches.append(name)
        elif _one_edit_apart(skeleton, reference_skeleton):
            matches.append(name)
    matches = sorted(confusable_matches or matches)
    if len(matches) != 1:
        return []

    reference = matches[0]
    evidence = (
        f"uses characters confusable with popular {ecosystem} package `{reference}`"
        if confusable_matches
        else f"is one edit from popular {ecosystem} package `{reference}`"
    )
    return [
        Finding(
            check="typosquat",
            severity="suspicious",
            weight=25,
            message=f"Package name `{original_name}` {evidence}",
        )
    ]
