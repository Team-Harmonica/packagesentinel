"""Command-line entry point.

Minimal printer so the pipeline is usable end to end; Tejas and Vedanti own the pretty
version. Exit codes: 0 safe/suspicious, 1 malicious, 2 usage/resolve error.
"""

from __future__ import annotations

import argparse
import json
import sys

from .detection import glassworm
from .detection.resolver import cleanup, resolve
from .detection.scanner import run_scanner
from .detection.scoring import build_verdict

BAND_COLORS = {"safe": "32", "suspicious": "33", "malicious": "31"}
SEV_COLORS = {"info": "2", "suspicious": "33", "malicious": "31"}


def _c(code: str, text: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def print_verdict(v: dict, color: bool) -> None:
    head = f"{v['band'].upper():<11}"
    print(f"{_c(BAND_COLORS[v['band']] + ';1', head, color)}"
          f"{v['package']}@{v['version'] or '?'}   score {v['score']}/100\n")
    caps = [f["message"].split(":")[0] for f in v["findings"] if f["check"] == "capability"]
    shown = [f for f in v["findings"] if f["check"] != "capability"]
    if caps:
        print(f"  capabilities: {', '.join(caps)}\n")
    if not shown:
        print("  no findings")
    for f in shown:
        sev = _c(SEV_COLORS[f["severity"]], f"[{f['severity']}]", color)
        print(f"  {sev:<12} {f['check']:<12} {f['location']}")
        print(f"      {f['message']}")
    if v.get("explanation"):
        print("\n  score breakdown:")
        for line in v["explanation"]:
            print(f"    {line}")
    if v["mismatches"]:
        print("\n  capability mismatches:")
        for m in v["mismatches"]:
            print(f"    - {m}")


def cmd_check(args) -> int:
    try:
        pkg_dir, meta = resolve(args.target, args.ecosystem)
    except Exception as exc:
        print(f"packagesentinel: {exc}", file=sys.stderr)
        return 2
    try:
        verdict = build_verdict(meta, run_scanner(pkg_dir, meta))
    finally:
        cleanup(meta)  # removes the temp dir of an extracted archive / registry fetch
    if args.json:
        print(json.dumps(verdict, indent=2, ensure_ascii=False))
    else:
        print_verdict(verdict, color=sys.stdout.isatty())
    return 1 if verdict["band"] == "malicious" else 0


def cmd_reveal(args) -> int:
    try:
        pkg_dir, _meta = resolve(args.target, args.ecosystem)
    except Exception as exc:
        print(f"packagesentinel: {exc}", file=sys.stderr)
        return 2
    try:
        hits = glassworm.reveal(pkg_dir)
    finally:
        cleanup(_meta)
    if args.json:
        print(json.dumps(hits, indent=2, ensure_ascii=False))
        return 0
    if not hits:
        print("no hidden Unicode found")
    for h in hits:
        print(f"{h['location']}  ({h['length']} hidden: {', '.join(h['kinds'])})")
        print(f"  you see:   {h['preview']}")
        if h["decoded"] is not None:
            print(f"  it hides:  {glassworm._visible(h['decoded'], 400)}   [{h['scheme']}]")
        elif h["scheme"]:
            print(f"  it hides:  {h['decoded_bytes']} bytes of non-text data   [{h['scheme']}]")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # harness commands own their own argument parsing
    if argv[:1] == ["eval"]:
        from .detection import evaluate
        return evaluate.main(argv[1:])
    if argv[:1] == ["diff"]:
        from .detection import diff
        return diff.main(argv[1:])
    if argv[:1] == ["calibrate"]:
        from .detection import calibrate
        return calibrate.main(argv[1:])

    p = argparse.ArgumentParser(prog="packagesentinel",
                                description="PackageSentinel: static package analysis for npm and PyPI.")
    p.epilog = "also: `packagesentinel diff <old> <new>` (local version diff), `packagesentinel eval` (precision/recall), `packagesentinel calibrate` (thresholds)"
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, help_ in (("check", cmd_check, "scan a package and print a verdict"),
                            ("reveal", cmd_reveal, "show invisible-Unicode hits, decoded")):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("target", help="path to an unpacked package")
        sp.add_argument("-e", "--ecosystem", choices=("npm", "pypi"), default="npm")
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.set_defaults(fn=fn)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
