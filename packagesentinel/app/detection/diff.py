"""Version-diff: what did the new version ADD?

    packagesentinel diff <old-folder> <new-folder>          (works today)
    packagesentinel diff <package> <old-version> <new-version>   (once acquisition supports version comparison)

Runs the full pipeline (resolve -> run_scanner -> score) on both versions and
compares them:

1. findings, by a stable fingerprint (check, file, normalized message), so a
   finding that only moved lines is "unchanged" and a new one is "added"
2. dependencies from meta["dependencies"]: added / removed / version-changed
   (a new dependency in a patch release is the event-stream hijack signature)
3. npm install scripts (preinstall / install / postinstall / prepare) from
   package.json, read as data, never run
4. files, by sha256: added / deleted / modified
5. verdict delta: old score+band -> new score+band, plus the update-risk combo:
   risky signals that first appear in a patch/minor bump add a bonus
   (UPDATE_RISK_* in scoring.py)

The headline sums it up in one line, e.g.
    clean at 1.0.0 → malicious at 1.0.1: added webhook_exfil, ssh_aws_read in
    scripts/setup.js; new postinstall script; new dependency flatmap-stream; score 0 → 100

Exit code 1 if the new version is malicious or in a worse band than the old one,
so it can gate dependency-update PRs in CI. Static only: nothing is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from . import scoring
from .resolver import resolve
from .scanner import Finding, iter_files, rel, run_scanner

BAND_RANK = {"safe": 0, "suspicious": 1, "malicious": 2}
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


# --- loading -----------------------------------------------------------------


def load(target: str, ecosystem: str = "npm", version: str | None = None) -> tuple[Path, dict]:
    """Turn a local folder, or a package name + version, into (pkg_dir, meta).

    RESOLVER CONTRACT: the by-name path needs `resolve(pkg, ecosystem, version=None)`
    (version optional, defaults to latest). The resolver currently in this repo is
    `resolve(pkg, ecosystem)` and only accepts local folders; Aryan is adding the
    version parameter. Until then only the local-folder path below works.
    """
    if version is None and Path(target).is_dir():
        return resolve(target, ecosystem)  # local folder: works today
    return resolve(target, ecosystem, version=version)  # by name: needs the contract above


# --- fingerprints ------------------------------------------------------------

_LINE_COL = re.compile(r":\d+(?::\d+)?")
_COUNTS = re.compile(r"\s*\((?:x\d+|\+\d+ more)\)")
_HEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
_BLOB = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_NUMBER = re.compile(r"\d+")


def location_file(location: str) -> str:
    """'scripts/setup.js:14:3 (decoded payload)' -> 'scripts/setup.js'"""
    return _LINE_COL.sub("", location).split(" (")[0].strip()


def normalize(message: str) -> str:
    message = _COUNTS.sub("", message)
    message = _HEX.sub("<hex>", message)
    message = _BLOB.sub("<blob>", message)
    return _NUMBER.sub("<n>", message).strip()


def fingerprint(f: Finding) -> tuple[str, str, str]:
    """Stable identity across versions: line numbers and counts drift, the
    file stays (an eval that moved into the postinstall script is news)."""
    return (f.check, location_file(f.location), normalize(f.message))


def diff_findings(old: list[Finding], new: list[Finding]) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """(added, removed, unchanged). Multiset semantics: two identical findings
    in the new version vs one in the old means one was added."""
    old_fp = Counter(fingerprint(f) for f in old)
    new_fp = Counter(fingerprint(f) for f in new)
    added_left = new_fp - old_fp
    removed_left = old_fp - new_fp
    added, unchanged, removed = [], [], []
    for f in new:
        fp = fingerprint(f)
        if added_left[fp] > 0:
            added_left[fp] -= 1
            added.append(f)
        else:
            unchanged.append(f)
    for f in old:
        fp = fingerprint(f)
        if removed_left[fp] > 0:
            removed_left[fp] -= 1
            removed.append(f)
    return added, removed, unchanged


# --- dependencies, install scripts, files -------------------------------------


def _as_dict(deps) -> dict[str, str]:
    if isinstance(deps, dict):
        return {str(k): str(v) for k, v in deps.items()}
    return {str(d): "" for d in deps or []}


def diff_dependencies(old_meta: dict, new_meta: dict) -> dict:
    old, new = _as_dict(old_meta.get("dependencies")), _as_dict(new_meta.get("dependencies"))
    return {
        "added": {k: new[k] for k in sorted(new.keys() - old.keys())},
        "removed": {k: old[k] for k in sorted(old.keys() - new.keys())},
        "changed": {k: {"from": old[k], "to": new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]},
    }


def install_scripts(pkg_dir: Path) -> dict[str, str]:
    manifest = Path(pkg_dir) / "package.json"
    if not manifest.is_file() or manifest.is_symlink():
        return {}
    try:
        scripts = json.loads(manifest.read_text(encoding="utf-8")).get("scripts") or {}
    except (ValueError, OSError, AttributeError):
        return {}
    return {k: str(v) for k, v in scripts.items() if k in INSTALL_SCRIPTS}


def diff_install_scripts(old_dir: Path, new_dir: Path) -> dict:
    old, new = install_scripts(old_dir), install_scripts(new_dir)
    return {
        "added": {k: new[k] for k in new if k not in old},
        "removed": {k: old[k] for k in old if k not in new},
        "changed": {k: {"from": old[k], "to": new[k]} for k in new if k in old and old[k] != new[k]},
    }


def file_hashes(pkg_dir: Path) -> dict[str, str]:
    out = {}
    for path in iter_files(pkg_dir):
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
        except OSError:
            continue
        out[rel(path, pkg_dir)] = h.hexdigest()
    return out


def diff_files(old_dir: Path, new_dir: Path) -> dict:
    old, new = file_hashes(old_dir), file_hashes(new_dir)
    return {
        "added": sorted(new.keys() - old.keys()),
        "deleted": sorted(old.keys() - new.keys()),
        "modified": sorted(k for k in old.keys() & new.keys() if old[k] != new[k]),
    }


# --- verdict delta -----------------------------------------------------------


def version_bump(old: str, new: str) -> str | None:
    """'patch' | 'minor' | 'major' | None (unparseable / not an upgrade)."""
    def parse(v: str):
        m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", v or "")
        return tuple(int(x) for x in m.groups()) if m else None
    a, b = parse(old), parse(new)
    if not a or not b or b <= a:
        return None
    return "major" if b[0] != a[0] else "minor" if b[1] != a[1] else "patch"


def _capabilities(findings: list[Finding]) -> set[str]:
    return {f.message.split(":")[0] for f in findings if f.check == "capability"}


def _band_word(band: str) -> str:
    return "clean" if band == "safe" else band


def headline(result: dict) -> str:
    old, new = result["old"], result["new"]
    parts = []
    if result["added_types"]:
        files = result["added_files"]
        where = f" in {', '.join(files[:3])}{' +more' if len(files) > 3 else ''}" if files else ""
        parts.append(f"added {', '.join(result['added_types'][:4])}{where}")
    for name in result["install_scripts"]["added"]:
        parts.append(f"new {name} script")
    for name in result["install_scripts"]["changed"]:
        parts.append(f"changed {name} script")
    deps = list(result["dependencies"]["added"])
    if deps:
        parts.append(f"new dependenc{'y' if len(deps) == 1 else 'ies'} {', '.join(deps[:3])}")
    if result["removed_types"] and not parts:
        parts.append(f"removed {', '.join(result['removed_types'][:4])}")
    if not parts:
        parts.append("no new risk signals")
    return (f"{_band_word(old['band'])} at {old['version']} → {_band_word(new['band'])} at {new['version']}: "
            f"{'; '.join(parts)}; score {old['score']} → {new['score']}")


def compare(old_dir: Path, old_meta: dict, new_dir: Path, new_meta: dict) -> dict:
    old_findings = run_scanner(old_dir, old_meta)
    new_findings = run_scanner(new_dir, new_meta)
    old_score, old_band, _ = scoring.score(old_findings, old_meta)
    new_score, new_band, new_expl = scoring.score(new_findings, new_meta)

    added, removed, unchanged = diff_findings(old_findings, new_findings)
    deps = diff_dependencies(old_meta, new_meta)
    scripts = diff_install_scripts(old_dir, new_dir)

    def ranked_types(fs: list[Finding]) -> list[str]:
        weights: dict[str, int] = {}
        for f in fs:
            t = scoring.finding_type(f)
            weights[t] = max(weights.get(t, 0), scoring.WEIGHTS.get(t, f.weight))
        return [t for t, w in sorted(weights.items(), key=lambda kv: -kv[1]) if w > 0]

    added_types = ranked_types([f for f in added if f.check != "capability"])
    removed_types = ranked_types([f for f in removed if f.check != "capability"])
    added_files = []
    for f in added:
        if f.check != "capability" and scoring.WEIGHTS.get(scoring.finding_type(f), f.weight) > 0:
            name = location_file(f.location)
            if name and name not in added_files:
                added_files.append(name)

    # update-risk combo: risky signals that first appear in a patch/minor release
    old_v = old_meta.get("version") or Path(old_dir).name
    new_v = new_meta.get("version") or Path(new_dir).name
    bump = version_bump(old_v, new_v)
    risky = set(added_types) & scoring.UPDATE_RISK_TYPES
    if scripts["added"] or scripts["changed"]:
        risky.add("new_install_script")
    update_risk = []
    if bump in scoring.UPDATE_RISK_BONUS and risky:
        bonus = scoring.UPDATE_RISK_BONUS[bump]
        new_score = min(100, new_score + bonus)
        new_band = "malicious" if new_band == "malicious" else scoring.band_for(new_score)
        update_risk.append(f"+{bonus} combo: risky signals introduced in a {bump} release "
                           f"(hijacked-update shape): {', '.join(sorted(risky))}")

    old_caps, new_caps = _capabilities(old_findings), _capabilities(new_findings)
    result = {
        "package": new_meta.get("name") or old_meta.get("name") or "",
        "old_version": old_v,
        "new_version": new_v,
        "bump": bump,
        "old": {"version": old_v, "score": old_score, "band": old_band},
        "new": {"version": new_v, "score": new_score, "band": new_band},
        "added_findings": [f.to_dict() for f in added],
        "removed_findings": [f.to_dict() for f in removed],
        "unchanged_count": len(unchanged),
        "added_types": added_types,
        "removed_types": removed_types,
        "added_files": added_files,
        "dependencies": deps,
        "install_scripts": scripts,
        "files": diff_files(old_dir, new_dir),
        "capabilities": {"added": sorted(new_caps - old_caps), "removed": sorted(old_caps - new_caps)},
        "explanation": new_expl + update_risk,
    }
    result["headline"] = headline(result)
    result["worse"] = BAND_RANK[new_band] > BAND_RANK[old_band]
    return result


def diff_dirs(old: str | Path, new: str | Path, ecosystem: str = "npm") -> dict:
    old_dir, old_meta = load(str(old), ecosystem)
    new_dir, new_meta = load(str(new), ecosystem)
    return compare(old_dir, old_meta, new_dir, new_meta)


def diff_versions(pkg: str, old: str, new: str, ecosystem: str = "npm") -> dict:
    old_dir, old_meta = load(pkg, ecosystem, version=old)
    new_dir, new_meta = load(pkg, ecosystem, version=new)
    return compare(old_dir, old_meta, new_dir, new_meta)


# --- CLI ---------------------------------------------------------------------

SEV_COLORS = {"info": "2", "suspicious": "33", "malicious": "31"}
BAND_COLORS = {"safe": "32", "suspicious": "33", "malicious": "31"}


def _c(code: str, text: str, on: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if on else text


def print_result(r: dict, color: bool) -> None:
    print(_c("1", r["headline"], color) + "\n")
    o, n = r["old"], r["new"]
    print(f"  {r['package']}  {o['version']} → {n['version']}" + (f"  ({r['bump']} bump)" if r["bump"] else ""))
    print(f"  {_c(BAND_COLORS[o['band']], o['band'].upper(), color)} {o['score']}/100  →  "
          f"{_c(BAND_COLORS[n['band']] + ';1', n['band'].upper(), color)} {n['score']}/100\n")

    shown = [f for f in r["added_findings"] if f["check"] != "capability"]
    print(f"  ADDED findings ({len(shown)})")
    for f in shown:
        sev = _c(SEV_COLORS[f["severity"]], f"[{f['severity']}]", color)
        print(f"    + {sev:<12} {f['check']:<18} {f['location']}")
        print(f"        {f['message']}")
    gone = [f for f in r["removed_findings"] if f["check"] != "capability"]
    if gone:
        print(f"\n  REMOVED findings ({len(gone)})")
        for f in gone:
            print(f"    - [{f['severity']}] {f['check']:<18} {f['location']}  {f['message'][:80]}")
    print(f"\n  unchanged findings: {r['unchanged_count']}")

    for label, d in (("install scripts", r["install_scripts"]), ("dependencies", r["dependencies"])):
        if any(d.values()):
            print(f"\n  {label}:")
            for k, v in d["added"].items():
                print(f"    + {k}: {v}")
            for k, v in d["removed"].items():
                print(f"    - {k}: {v}")
            for k, v in d["changed"].items():
                print(f"    ~ {k}: {v['from']} → {v['to']}")
    f = r["files"]
    if any(f.values()):
        print("\n  files:")
        for p in f["added"]:
            print(f"    + {p}")
        for p in f["deleted"]:
            print(f"    - {p}")
        for p in f["modified"]:
            print(f"    ~ {p}")
    if r["capabilities"]["added"]:
        print(f"\n  new capabilities: {', '.join(r['capabilities']['added'])}")
    if r["explanation"]:
        print("\n  new version score breakdown:")
        for line in r["explanation"]:
            print(f"    {line}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="packagesentinel diff", description="What did the new version add?")
    p.add_argument("targets", nargs="+", metavar="TARGET",
                   help="<old-folder> <new-folder>, or <package> <old-version> <new-version>")
    p.add_argument("-e", "--ecosystem", choices=("npm", "pypi"), default="npm")
    p.add_argument("--json", action="store_true", help="machine-readable output for the diff view")
    args = p.parse_args(argv)
    try:
        if len(args.targets) == 2:
            result = diff_dirs(args.targets[0], args.targets[1], args.ecosystem)
        elif len(args.targets) == 3:
            result = diff_versions(*args.targets, ecosystem=args.ecosystem)
        else:
            p.error("expected 2 folders or a package and 2 versions")
    except TypeError as exc:
        if "version" in str(exc):
            print("packagesentinel diff: the resolver does not take a version yet "
                  "(needs resolve(pkg, ecosystem, version=None)); pass two local folders for now",
                  file=sys.stderr)
            return 2
        raise
    except Exception as exc:
        print(f"packagesentinel diff: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_result(result, color=sys.stdout.isatty())
    return 1 if result["new"]["band"] == "malicious" or result["worse"] else 0
