"""Registry-metadata checks: signals about who published a package and when.

Reads only the meta dict from the resolver (app.acquisition); never the
network, never package code. Missing data means "no finding", not a guess.

    META001  brand-new package          (first published < NEW_PACKAGE_DAYS ago)
    META002  very low downloads         (< LOW_DOWNLOADS per week)
    META003  maintainer change          (no one who maintained the previous release maintains this one)
    META004  missing / mismatched repo  (no repo link, or it points at a different popular package)
    META005  suspicious version jump    (skips many majors, or a dependency-confusion style 99.x)

Messages are worded to match scoring.TYPE_RULES (maintainer / download / repo /
publish / "Version "), so each finding scores as exactly one type.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .scanner import Finding
from .scoring import LOW_DOWNLOADS, NEW_PACKAGE_DAYS, POPULAR_DOWNLOADS

CHECK = "metadata"
HUGE_MAJOR = 99       # first-release majors like 99.0.0 are the dependency-confusion signature
BIG_JUMP = 5          # majors skipped in one release


# --- shared with typosquat ---------------------------------------------------


def age_days(meta: dict) -> tuple[int, str] | None:
    """(days since the package first appeared, which field said so)."""
    for key in ("created", "published"):
        value = meta.get(key)
        if not value:
            continue
        try:
            when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - when).days), key
    return None


def weak_signals(meta: dict) -> list[str]:
    """Reasons this package has no established reputation (new / barely used)."""
    out = []
    downloads = meta.get("downloads")
    if isinstance(downloads, int) and not isinstance(downloads, bool) and downloads < LOW_DOWNLOADS:
        out.append(f"only {downloads} weekly downloads")
    age = age_days(meta)
    if age and age[0] < NEW_PACKAGE_DAYS:
        out.append(f"first published {age[0]} day(s) ago")
    return out


def is_popular(meta: dict) -> bool:
    downloads = meta.get("downloads")
    return isinstance(downloads, int) and downloads > POPULAR_DOWNLOADS


def has_registry_data(meta: dict) -> bool:
    return isinstance(meta.get("downloads"), int) or age_days(meta) is not None


# --- the five rules ------------------------------------------------------------


def _finding(rule: str, category: str, severity: str, weight: int, confidence: float,
             message: str) -> Finding:
    return Finding(CHECK, severity, weight, message, "package metadata",
                   rule_id=rule, category=category, confidence=confidence)


def _new_package(meta: dict) -> list[Finding]:
    age = age_days(meta)
    if not age or age[0] >= NEW_PACKAGE_DAYS:
        return []
    what = "Package first published" if age[1] == "created" else "This release was published"
    return [_finding("META001", "package_reputation", "info", 5, 0.6,
                     f"{what} {age[0]} day(s) ago (under {NEW_PACKAGE_DAYS} days)")]


def _low_downloads(meta: dict) -> list[Finding]:
    downloads = meta.get("downloads")
    if not isinstance(downloads, int) or isinstance(downloads, bool) or downloads >= LOW_DOWNLOADS:
        return []
    return [_finding("META002", "package_reputation", "info", 5, 0.6,
                     f"Only {downloads} weekly downloads (under {LOW_DOWNLOADS})")]


def _maintainer_change(meta: dict) -> list[Finding]:
    before = {str(m).lower() for m in meta.get("previous_maintainers") or [] if m}
    now = {str(m).lower() for m in meta.get("maintainers") or [] if m}
    if not before or not now or before & now:
        return []
    since = meta.get("previous_version") or "the previous release"
    return [_finding("META003", "maintainer_change", "suspicious", 15, 0.75,
                     f"Maintainers fully replaced since {since}: now {', '.join(sorted(now))}; "
                     f"previously {', '.join(sorted(before))} (possible account takeover)")]


def _norm(text: str) -> str:
    return re.sub(r"[-_.]+", "-", text.lower()).strip("-")


def _repo_name(url: str) -> str | None:
    m = re.search(r"(?:github\.com|gitlab\.com|bitbucket\.org)[/:]([^/\s]+)/([^/\s#?]+)", url, re.I)
    if not m:
        return None
    return _norm(re.sub(r"\.git$", "", m.group(2), flags=re.I))


def _repo(meta: dict) -> list[Finding]:
    url = meta.get("repo_url")
    if not url:
        # A local folder / upload has no registry context, and plenty of fine
        # tarballs omit "repository"; only flag it alongside registry data.
        if not has_registry_data(meta):
            return []
        return [_finding("META004", "repository_integrity", "info", 5, 0.4,
                         "No source repository linked in the package metadata")]
    repo = _repo_name(str(url))
    if not repo:
        return []
    from .typosquat import POPULAR_PACKAGES  # lazy: typosquat imports this module

    name = str(meta.get("name") or "")
    scope, _, bare = name[1:].partition("/") if name.startswith("@") else ("", "", name)
    bare, scope = _norm(bare), _norm(scope)
    related = repo == scope or repo in bare or bare in repo
    popular = {_norm(p) for names in POPULAR_PACKAGES.values() for p in names if not p.startswith("@")}
    if related or not bare or repo not in popular or bare in popular:
        return []
    return [_finding("META004", "repository_integrity", "suspicious", 15, 0.7,
                     f"Repository link points to `{repo}`, a different popular package, not `{name}` "
                     f"(possible star-jacking: borrowing another project's reputation)")]


def _major(version) -> int | None:
    m = re.match(r"^v?(\d+)(?:\.|$)", str(version or "").strip())
    return int(m.group(1)) if m else None


def _version_jump(meta: dict) -> list[Finding]:
    version = meta.get("version")
    new, old = _major(version), _major(meta.get("previous_version"))
    if new is None:
        return []
    if old is not None and new - old >= BIG_JUMP:
        return [_finding("META005", "version_anomaly", "suspicious", 10, 0.6,
                         f"Version jumps from {meta['previous_version']} to {version} "
                         f"(skips {new - old - 1} major versions)")]
    if new >= HUGE_MAJOR and (old is None or new - old > 1):
        return [_finding("META005", "version_anomaly", "suspicious", 10, 0.7,
                         f"Version {version} has an unusually high major number "
                         f"(dependency-confusion pattern: outranks private package versions)")]
    return []


RULES = (_new_package, _low_downloads, _maintainer_change, _repo, _version_jump)


def check(_pkg_dir: Path, meta: dict) -> list[Finding]:
    if not isinstance(meta, dict) or not (meta.get("name") or meta.get("package_name")):
        return []
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(meta))
    return findings
