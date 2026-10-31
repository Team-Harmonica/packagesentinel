"""Calibration: pick band thresholds from data instead of by hand.

    python -m harmonica calibrate [--no-corpus] [--corpus FILE] [--workers N]

Scores every labelled package:
  * test-samples/malicious/*  -> label malicious
  * test-samples/benign/*     -> label benign
  * the benign corpus (calibration/benign-corpus.txt): real, legitimate code
    split into package-sized units (stdlib modules, npm deps, VS Code
    extensions, Electron app node_modules, ...)

Then prints both score distributions and suggests Suspicious/Malicious
thresholds in the gap between the clusters, with precision/recall at those
thresholds. If the clusters overlap, it says so loudly: that means the WEIGHTS
are wrong, and no threshold can fix it.

It only prints a suggestion. To adopt it, edit THRESHOLDS in scoring.py.
Nothing is executed; this only runs the static scanner over the files.
"""

from __future__ import annotations

import argparse
import glob
import math
import os
import shutil
import sysconfig
import tempfile
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import scoring
from .resolver import resolve
from .scanner import run_scanner

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "test-samples"
DEFAULT_CORPUS = REPO / "calibration" / "benign-corpus.txt"

EXPAND = {"node_modules", "site-packages", "dist-packages"}
SKIP = {"__pycache__", ".bin", ".cache", "lib-dynload"}
SOURCE_SUFFIX = {".py", ".js", ".mjs", ".cjs"}
MARGIN = 10  # points between the highest benign score and the suggested malicious threshold


@dataclass
class Result:
    name: str
    label: str  # "malicious" | "benign"
    source: str  # "samples" | "corpus"
    score: int = 0
    band: str = "safe"
    forced: bool = False  # has a confirmed (severity=malicious) finding: band is malicious regardless
    confirmed: str = ""
    explanation: list[str] = field(default_factory=list)
    error: str = ""


# --- corpus discovery --------------------------------------------------------


def _resolve_root(line: str) -> list[Path]:
    if line == "@stdlib":
        return [Path(sysconfig.get_paths()["stdlib"])]
    if line == "@site-packages":
        return sorted({Path(sysconfig.get_paths()[k]) for k in ("purelib", "platlib")})
    return [Path(p) for p in sorted(glob.glob(line, recursive=True))]


def corpus_roots(corpus_file: Path) -> list[Path]:
    roots: list[Path] = []
    for raw in corpus_file.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #")[0].strip()
        if line and not line.startswith("#"):
            roots += [p for p in _resolve_root(line) if p.is_dir()]
    # drop roots nested inside another root (globs like **/node_modules overlap)
    roots = sorted(set(roots))
    return [r for r in roots if not any(o != r and o in r.parents for o in roots)]


def _units_in(root: Path, stdlib: Path) -> list[Path]:
    units: list[Path] = []
    try:
        children = sorted(root.iterdir())
    except OSError:
        return units
    for child in children:
        name = child.name
        if name in SKIP or name.startswith(".") or name.endswith((".dist-info", ".egg-info")):
            continue
        if child.is_symlink():
            continue
        if root == stdlib and name in EXPAND:
            continue  # site-packages has its own corpus line
        if child.is_dir():
            if name in EXPAND or name.startswith("@"):
                units += _units_in(child, stdlib)
            else:
                units.append(child)
        elif child.suffix in SOURCE_SUFFIX:
            units.append(child)
    return units


def corpus_units(corpus_file: Path) -> list[Path]:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    units: list[Path] = []
    for root in corpus_roots(corpus_file):
        units += _units_in(root, stdlib)
    return units


# --- scoring -----------------------------------------------------------------


def _score_unit(job: tuple[str, str, str, str]) -> Result:
    path_s, name, label, source = job
    path = Path(path_s)
    result = Result(name=name, label=label, source=source)
    try:
        if path.is_file():  # single-module unit: scan it as a one-file package
            with tempfile.TemporaryDirectory() as tmp:
                shutil.copy2(path, Path(tmp) / path.name)
                findings = run_scanner(tmp, {"name": name})
            meta = {"name": name}
        else:
            if source == "samples":
                _, meta = resolve(str(path))
            else:
                meta = {"name": name}
            findings = run_scanner(path, meta)
        result.score, result.band, result.explanation = scoring.score(findings, meta)
        confirmed = next((f for f in findings if f.severity == "malicious"), None)
        if confirmed:  # stage 5 makes this malicious whatever the thresholds are
            result.forced = True
            result.confirmed = f"{confirmed.check}: {confirmed.message[:90]} [{confirmed.location}]"
    except Exception as exc:  # a broken unit must not kill the run
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def collect(corpus_file: Path | None = DEFAULT_CORPUS, workers: int | None = None,
            progress: bool = True) -> list[Result]:
    jobs: list[tuple[str, str, str, str]] = []
    for label in ("malicious", "benign"):
        for d in sorted((SAMPLES / label).iterdir()) if (SAMPLES / label).is_dir() else []:
            if d.is_dir():
                jobs.append((str(d), d.name, label, "samples"))
    if corpus_file is not None and corpus_file.is_file():
        for u in corpus_units(corpus_file):
            parent = u.parent.name
            name = f"{parent}/{u.name}" if parent.startswith("@") else u.name
            jobs.append((str(u), name, "benign", "corpus"))

    results: list[Result] = []
    with ProcessPoolExecutor(max_workers=workers or os.cpu_count()) as pool:
        for i, r in enumerate(pool.map(_score_unit, jobs, chunksize=4), 1):
            results.append(r)
            if progress and (i % 50 == 0 or i == len(jobs)):
                print(f"\r  scanned {i}/{len(jobs)} packages", end="", flush=True)
    if progress:
        print()
    return results


# --- metrics -----------------------------------------------------------------


def band_at(r: Result, thresholds: dict) -> str:
    if r.forced or r.score >= thresholds["malicious"]:
        return "malicious"
    return "suspicious" if r.score >= thresholds["suspicious"] else "safe"


def metrics(results: list[Result], thresholds: dict, positive: set[str] = frozenset({"malicious"})) -> dict:
    tp = fp = tn = fn = 0
    for r in results:
        if r.error:
            continue
        predicted = band_at(r, thresholds) in positive
        actual = r.label == "malicious"
        tp += predicted and actual
        fp += predicted and not actual
        fn += actual and not predicted
        tn += not predicted and not actual
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "fpr": fpr}


def _percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    return s[min(len(s) - 1, math.ceil(q * len(s)) - 1)]


def suggest(results: list[Result]) -> dict:
    """Thresholds in the gap between the benign and malicious score clusters."""
    ok = [r for r in results if not r.error]
    mal = [r.score for r in ok if r.label == "malicious"]
    # benign packages forced to malicious by severity can't be fixed by thresholds
    ben = [r.score for r in ok if r.label == "benign" and not r.forced]
    max_ben, min_mal = (max(ben) if ben else 0), (min(mal) if mal else 100)
    overlap = max_ben >= min_mal
    if not overlap:
        # just above the benign cluster: with few malicious samples (all scoring high),
        # a midpoint would sit unrealistically high and cost recall on real malware
        malicious_at = min(min_mal, max_ben + MARGIN)
    else:  # best F1 boundary, but this is a symptom of bad weights
        best = max(range(1, 101), key=lambda t: _f1(ok, t))
        malicious_at = best
    # suspicious = "worth a look": above 95% of benign packages, never above malicious
    suspicious_at = max(1, min(malicious_at, _percentile(ben, 0.95) + 1))
    return {"malicious": malicious_at, "suspicious": suspicious_at, "overlap": overlap,
            "max_benign": max_ben, "min_malicious": min_mal}


def _f1(results: list[Result], t: int) -> float:
    m = metrics(results, {"malicious": t, "suspicious": t})
    p, r = m["precision"], m["recall"]
    return 2 * p * r / (p + r) if p + r else 0.0


# --- report ------------------------------------------------------------------


def _histogram(scores: list[int], width: int = 40) -> list[str]:
    buckets = [0] * 11
    for s in scores:
        buckets[min(10, s // 10)] += 1
    peak = max(buckets) or 1
    lines = []
    for i, n in enumerate(buckets):
        label = "100" if i == 10 else f"{i * 10:>2}-{i * 10 + 9}"
        bar = "#" * max(1 if n else 0, round(n / peak * width))
        lines.append(f"    {label:>6} | {bar} {n if n else ''}")
    return lines


def print_metrics(name: str, m: dict) -> None:
    print(f"  {name}: precision {m['precision']:.1%}  recall {m['recall']:.1%}  "
          f"false-positive rate {m['fpr']:.2%}   (TP {m['tp']}  FP {m['fp']}  TN {m['tn']}  FN {m['fn']})")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harmonica calibrate", description=__doc__.split("\n\n")[0])
    p.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS, help="benign corpus list file")
    p.add_argument("--no-corpus", action="store_true", help="labelled samples only (fast)")
    p.add_argument("--workers", type=int, default=None)
    args = p.parse_args(argv)

    results = collect(None if args.no_corpus else args.corpus, args.workers)
    errors = [r for r in results if r.error]
    ok = [r for r in results if not r.error]
    mal = [r for r in ok if r.label == "malicious"]
    ben = [r for r in ok if r.label == "benign"]
    print(f"\n{len(mal)} malicious, {len(ben)} benign "
          f"({sum(r.source == 'samples' for r in ben)} samples + {sum(r.source == 'corpus' for r in ben)} "
          f"corpus packages), {len(errors)} errors")

    print("\nMALICIOUS score distribution")
    print("\n".join(_histogram([r.score for r in mal])))
    print("\nBENIGN score distribution (severity-override cases excluded, listed below)")
    print("\n".join(_histogram([r.score for r in ben if not r.forced])))

    forced_benign = [r for r in ben if r.forced]
    if forced_benign:
        print(f"\nBenign packages forced to MALICIOUS by a confirmed-severity finding ({len(forced_benign)}).")
        print("Thresholds cannot fix these; they need a detector fix or are true positives on policy:")
        for r in forced_benign:
            print(f"  - {r.name}: {r.confirmed}")

    s = suggest(ok)
    print(f"\nHighest benign score: {s['max_benign']}    lowest malicious score: {s['min_malicious']}")
    if s["overlap"]:
        print("\n" + "!" * 78)
        print("!! CLUSTERS OVERLAP: some benign packages score as high as malicious ones.")
        print("!! That means the WEIGHTS are wrong, not the thresholds. Fix weights first.")
        print("!" * 78)
        for r in sorted(ben, key=lambda r: -r.score):
            if r.score < s["min_malicious"] or r.forced:
                continue
            print(f"  {r.score:>3}  {r.name}")
            for line in r.explanation[:4]:
                print(f"         {line}")
    else:
        print(f"Clean gap between clusters ({s['max_benign']} < {s['min_malicious']}).")

    print("\nTop-scoring benign packages:")
    for r in sorted((r for r in ben if not r.forced), key=lambda r: -r.score)[:8]:
        print(f"  {r.score:>3}  {r.name:<40} {r.explanation[0][:80] if r.explanation else ''}")

    current = scoring.THRESHOLDS
    suggested = {"malicious": s["malicious"], "suspicious": s["suspicious"]}
    print(f"\nCurrent   THRESHOLDS = {current}")
    print_metrics("  malicious band ", metrics(ok, current))
    print_metrics("  flagged (susp+)", metrics(ok, current, {"suspicious", "malicious"}))
    print(f"Suggested THRESHOLDS = {suggested}" + ("   <- UNRELIABLE, clusters overlap" if s["overlap"] else ""))
    print_metrics("  malicious band ", metrics(ok, suggested))
    print_metrics("  flagged (susp+)", metrics(ok, suggested, {"suspicious", "malicious"}))
    if len(mal) < 20:
        print(f"\nNote: only {len(mal)} malicious samples. Recall is measured on a small set; add more "
              "fixtures to test-samples/malicious/ to make it meaningful.")
    for r in errors:
        print(f"  error: {r.name}: {r.error}")
    print("\nTo adopt the suggestion, edit THRESHOLDS in harmonica/scoring.py.")
    return 1 if s["overlap"] else 0
