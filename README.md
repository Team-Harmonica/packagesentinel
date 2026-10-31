# Harmonica

**Scan an npm or PyPI package for malicious code *before* you install it, without ever running it.**

Harmonica downloads a package, unpacks it, reads every file, and decides whether
it is safe. It only does static analysis. It runs on your machine, needs no
cloud service, and explains every verdict line by line.

```
$ harmonica check test-samples/malicious/glassworm-demo
MALICIOUS  glassworm-demo@1.0.0   score 100/100

  [malicious]  glassworm    index.js:4:19
      Hidden payload: 161 invisible variation-selector codepoints inside a string
      that looks empty decode (variation selectors as bytes) to code:
      `console.log("[harmonica fixture] hidden code ran. A real worm would …`

$ harmonica reveal test-samples/malicious/glassworm-demo
index.js:4:19  (161 hidden: variation-selector)
  you see:   const settings = "⟦161 hidden variation-selector⟧";
  it hides:  console.log("[harmonica fixture] hidden code ran. A real worm would now
             read " + require("os").homedir() + "/.ssh/id_rsa and POST it to …");
```

---

## Why this exists

`npm audit`, Snyk and Dependabot are **reactive**. They match your dependencies
against databases of *already published* advisories. A malicious package
published an hour ago has no CVE. Neither does a typosquat, a credential
stealer, or a hijacked maintainer account shipping a poisoned patch release, so
none of those tools will flag it.

Harmonica is **proactive**. It looks at what the code *does* and ignores what has
been reported about it. It also covers three blind spots that the incumbents miss:

| Blind spot | What Harmonica does |
|---|---|
| **Invisible-Unicode payloads** ([GlassWorm](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace)-style) | Reads files as raw bytes, finds code hidden in variation selectors, tag characters, zero-width runs and private-use codepoints, **decodes it back to visible text**, and scans the recovered code. |
| **Malicious updates** | Version-diff mode scans `v2.3.0` and `v2.3.1` and reports what changed: *"clean at 2.3.0, added a credential stealer at 2.3.1."* |
| **Capability mismatches** | Builds a profile of what the package can do (filesystem / network / process / env) and flags capabilities that don't fit its stated purpose. A math library has no reason to open a socket. |

---

## How it works

```
  harmonica check <pkg>            harmonica diff <pkg> <old> <new>
          │                                   │
          ▼                                   │  (runs the whole pipeline twice,
  ┌──────────────────┐                        │   diffs findings by fingerprint
  │ RESOLVE + UNPACK │  npm / PyPI / local    │   and diffs new dependencies)
  └────────┬─────────┘                        │
           │ (pkg_dir, meta)                  ▼
  ┌────────▼───────────────────────────────────────────────┐
  │ SCANNER                                                 │
  │  I.   raw bytes   glassworm · stego · install hooks     │
  │  II.  parsed code dangerous calls · credential access · │
  │                   network exfil · dynamic fetch ·       │
  │                   obfuscation                           │
  │  III. name + meta typosquat · metadata red flags        │
  └────────┬────────────────────────────────────────────────┘
           │ list[Finding]
  ┌────────▼─────────┐   ┌──────────────────────────┐
  │ CAPABILITY       │──▶│ SCORING                  │  weighted sum + combination
  │ PROFILE          │   │ Safe / Suspicious /      │  rules (weak signals together
  └──────────────────┘   │ Malicious                │  = strong signal)
                         └────────┬─────────────────┘
                                  ▼
                       Verdict JSON  →  CLI (exit code gates CI)  ·  Web UI
```

Every stage after RESOLVE works only with "an unpacked directory + a `meta`
dict", so the same scanner handles npm, PyPI and local folders.

### Why raw bytes first?

Editors, diff viewers and most linters hide or ignore invisible codepoints. An
"empty" string `""` can carry kilobytes of code encoded as variation selectors,
and a reviewer looking at the diff sees nothing. Harmonica's first pass reads the
bytes before any tokenizer or parser normalizes them, so nothing hidden that
way gets past it.

---

## What it detects

| Group | Check | Looks for | Status |
|---|---|---|---|
| I. Raw bytes | `glassworm` | Variation selectors (U+FE00–FE0F, U+E0100–E01EF), tag characters (U+E0000–E007F), zero-width chars (U+200B–200D, U+2060, U+FEFF), private-use (U+E000–F8FF, U+F0000+), Trojan-Source bidi controls, invisible identifier fillers. Decodes payloads and rescans them. Understands legitimate uses (emoji, flags, CJK variants, Indic/Persian joiners, icon fonts) so they don't trigger false alarms. | ✅ working |
| I. Raw bytes | `stego` | Data after PNG `IEND`, abnormally high image entropy, image-lib + download + exec combos | 🚧 stub |
| I. Raw bytes | `install_hooks` | npm `preinstall`/`postinstall`, `setup.py` code execution | 🚧 stub (Aryan) |
| II. Code | `code_scan` | **dangerous calls** (`eval`, `new Function`, `child_process`, `subprocess`, `os.system`); **credential access** (`~/.ssh`, `~/.aws`, `.npmrc`, browser/wallet stores, secret env vars, `JSON.stringify(process.env)`); **network exfil** (Discord/Telegram webhooks, paste/tunnel hosts, raw-IP URLs, secrets + endpoint in one file); **dynamic fetch** (`exec(urlopen())`, `.then(eval)`, `curl \| sh`); **obfuscation** (decode-then-exec, base64 that decodes to code and is rescanned, `obj["eval"]()`, obfuscator identifiers). Python uses the stdlib `ast`; JS uses a comment/string-aware lexer. | ✅ working |
| III. Meta | `typosquat` | Names one edit away from a popular package (and not popular itself) | 🚧 stub (Aryan) |
| III. Meta | `metadata` | Brand-new package, few downloads, maintainer change, no repo | 🚧 stub (Aryan) |
| — | `profile` | Capability buckets + purpose mismatch | 🚧 stub |
| — | `scoring` | Weighted score + combination rules → band | 🟡 placeholder (sum of weights) |
| — | `diff` | Version-diff wrapper | 🚧 stub |

---

## Quickstart

Requires Python 3.10+. There are no third-party dependencies.

```bash
git clone <this repo> && cd supply-chain-guardian
pip install -e .            # optional; gives you the `harmonica` command

# scan a local package directory
harmonica check test-samples/malicious/glassworm-demo
harmonica check test-samples/benign/emoji-utils

# machine-readable verdict
harmonica check test-samples/malicious/glassworm-demo --json

# show every invisible-Unicode hit, decoded ("invisible -> visible")
harmonica reveal test-samples/malicious/glassworm-demo

# without installing
python -m harmonica check <path>
```

**Exit codes:** `0` safe or suspicious, `1` malicious, `2` usage/resolve
error. Drop `harmonica check` into CI to block a malicious dependency.

---

## The contract

These types connect the three workstreams. **Do not rename fields.**

```python
@dataclass
class Finding:                 # every check returns list[Finding]
    check: str                 # e.g. "glassworm"
    severity: str              # "info" | "suspicious" | "malicious"
    weight: int                # contribution to the score
    message: str               # human-readable reason line (shown as evidence)
    location: str = ""         # "path/in/pkg:line:col"
```

```python
meta = {                       # produced by resolve(), read by group III checks
    "name", "ecosystem", "version", "published", "downloads",
    "maintainers", "repo_url", "dependencies",
}
```

```python
resolve(pkg, ecosystem)       -> (pkg_dir, meta)
run_scanner(pkg_dir, meta)    -> list[Finding]
build_verdict(pkg, findings)  -> dict
```

```jsonc
// Verdict JSON: what the CLI and web UI render
{
  "package": "glassworm-demo",
  "version": "1.0.0",
  "score": 100,
  "band": "malicious",          // "safe" | "suspicious" | "malicious"
  "findings": [ { "check": "...", "severity": "...", "weight": 0,
                  "message": "...", "location": "..." } ],
  "capabilities": { },          // filesystem / network / process / env
  "mismatches": [ ]
}
```

To add a check, write `def check(pkg_dir: Path, meta: dict) -> list[Finding]`
and register it in `_check_groups()` in `harmonica/scanner.py`. If a check
raises, the scan keeps going and records an `info` finding.

---

## Repository layout

```
harmonica/
  scanner.py     Finding + run_scanner() orchestrator + file walker
  glassworm.py   invisible-Unicode detection, decoding, reveal()
  code_scan.py   AST detectors (also rescans decoded GlassWorm payloads)
  stego.py       image steganography red flags
  scoring.py     weighted + combination scoring, build_verdict()
  profile.py     capability profile + mismatch
  diff.py        version-diff mode
  resolver.py    resolve(): npm / PyPI / local     (Aryan)
  hooks.py       install-hook detection            (Aryan)
  metadata.py    metadata red flags                (Aryan)
  typosquat.py   typosquat detection               (Aryan)
  cli.py         command-line entry point          (pretty printer: Tejas, Vedanti)
test-samples/
  malicious/     hand-made, INERT fixtures that mimic attack shapes
    glassworm-demo/  hidden payloads in variation selectors / tags / zero-width
    fake-stealer/    postinstall reading ~/.ssh + ~/.aws, Discord-style webhook
    py-dropper/      exec(urlopen(...)), exec(b64decode(...)), secret env reads
  benign/        clean packages that must NOT flag
    emoji-utils/     emoji, flags, CJK variants, Indic/Persian joiners, icon fonts
    clean-math/      Function("return this"), scary words in comments, a build script
tools/
  make_samples.py  regenerates fixtures that contain invisible characters
tests/             unit tests (python -m unittest)
```

## Team

| Who | Owns |
|---|---|
| **Aryan** | Resolve/unpack (npm, PyPI, local), install hooks, metadata red flags, typosquat |
| **Tejas & Vedanti** | Frontend: CLI pretty-printer + web UI (verdict card, GlassWorm reveal, diff view, stats) |
| **Varun** | Scanner spine, GlassWorm, code scan, stego, scoring, capability profile, version-diff, eval harness |

---

## False-positive testing

Every detector was also run against large amounts of real, legitimate code:
Python's standard library and site-packages, and the JS bundled with VS Code,
GitHub Copilot, Discord, Obsidian, Signal and npm itself (thousands of files).
After tuning, the whole corpus produces **two** malicious findings, both from a
Copilot shim that genuinely spawns `curl … | bash`. Rules that held up:

- A single weak signal (one `eval`, one credential path) never reaches *malicious*.
  Malicious needs a precise pattern (decode-then-exec, fetch-then-exec, hidden
  code) or a combination.
- Mentions are not uses: comments, docstrings, sentences in strings, deny-lists,
  and string data are kept apart from executable code.
- "Same file" co-occurrence rules only apply to files under 100 KB. In a 10 MB
  bundle, everything co-occurs.

## Safety

- **Harmonica never executes package code.** It does not install, import,
  `require`, or run setup scripts. Everything is read as bytes or parsed to an AST.
- Symlinks inside packages are not followed, so a package can't point the
  scanner at files outside its own directory.
- Everything in `test-samples/malicious/` is a **hand-written, inert fixture**.
  The fixtures copy the *shape* of real attacks (a hidden payload, an exfil URL
  on a reserved `.invalid` domain) so the detectors have something to find, but
  they contain no working malware. Never commit real malware samples to this repo.

## Development

```bash
python -m unittest discover -s tests -v
python tools/make_samples.py         # regenerate invisible-Unicode fixtures
```
