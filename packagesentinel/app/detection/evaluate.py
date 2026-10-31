"""Precision / recall harness: the headline numbers.

    packagesentinel eval [--no-corpus] [--corpus FILE] [--json]

Runs the real pipeline (run_scanner + scoring with the current THRESHOLDS)
over the labelled samples and the benign corpus, then prints precision,
recall, false-positive rate and the confusion matrix.

"Positive" = band malicious. The "flagged" row also counts suspicious as a
positive, i.e. "would a human be asked to look at this package".
`--json` prints the same numbers for the web UI's stats panel.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import calibrate, scoring

BANDS = ("safe", "suspicious", "malicious")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="packagesentinel eval", description=__doc__.split("\n\n")[0])
    p.add_argument("--corpus", type=Path, default=calibrate.DEFAULT_CORPUS)
    p.add_argument("--no-corpus", action="store_true", help="labelled samples only (fast)")
    p.add_argument("--workers", type=int, default=None)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    results = calibrate.collect(None if args.no_corpus else args.corpus, args.workers, progress=not args.json)
    ok = [r for r in results if not r.error]
    th = scoring.THRESHOLDS
    strict = calibrate.metrics(ok, th)
    flagged = calibrate.metrics(ok, th, {"suspicious", "malicious"})
    matrix = {label: {b: 0 for b in BANDS} for label in ("malicious", "benign")}
    for r in ok:
        matrix[r.label][calibrate.band_at(r, th)] += 1

    if args.json:
        print(json.dumps({
            "thresholds": th,
            "packages": {"malicious": sum(matrix["malicious"].values()),
                         "benign": sum(matrix["benign"].values()),
                         "benign_corpus": sum(r.source == "corpus" for r in ok)},
            "malicious_band": strict, "flagged": flagged, "confusion": matrix,
            "false_positives": [{"package": r.name, "score": r.score, "band": calibrate.band_at(r, th),
                                 "why": r.explanation[:3]} for r in ok
                                if r.label == "benign" and calibrate.band_at(r, th) == "malicious"],
            "false_negatives": [{"package": r.name, "score": r.score, "band": calibrate.band_at(r, th)}
                                for r in ok if r.label == "malicious" and calibrate.band_at(r, th) != "malicious"],
            "errors": len(results) - len(ok),
        }, indent=2))
        return 0

    n_mal, n_ben = sum(matrix["malicious"].values()), sum(matrix["benign"].values())
    n_corpus = sum(r.source == "corpus" for r in ok)
    print(f"\nPackageSentinel evaluation   thresholds {th}")
    print(f"{n_mal} malicious packages, {n_ben} benign packages ({n_corpus} from the real-code corpus)\n")
    print("Confusion matrix (rows = truth, columns = verdict band)")
    print(f"  {'':>11} {'safe':>8} {'suspicious':>11} {'malicious':>10}")
    for label in ("malicious", "benign"):
        row = matrix[label]
        print(f"  {label:>11} {row['safe']:>8} {row['suspicious']:>11} {row['malicious']:>10}")
    print()
    calibrate.print_metrics("malicious band ", strict)
    calibrate.print_metrics("flagged (susp+)", flagged)

    fps = [r for r in ok if r.label == "benign" and calibrate.band_at(r, th) == "malicious"]
    fns = [r for r in ok if r.label == "malicious" and calibrate.band_at(r, th) != "malicious"]
    if fps:
        print(f"\nFalse positives ({len(fps)}):")
        for r in sorted(fps, key=lambda r: -r.score):
            print(f"  {r.score:>3}  {r.name}")
            for line in r.explanation[:3]:
                print(f"         {line}")
    if fns:
        print(f"\nMissed malicious ({len(fns)}):")
        for r in fns:
            print(f"  {r.score:>3}  {r.name}  -> {calibrate.band_at(r, th)}")
    errors = [r for r in results if r.error]
    for r in errors:
        print(f"  error: {r.name}: {r.error}")
    return 0
