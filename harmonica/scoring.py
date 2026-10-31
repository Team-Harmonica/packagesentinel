"""Scoring: turn a list of Findings into (score, band, explanation).

All the judgement lives in the config tables at the top of this file. The
logic below them is lookups and arithmetic. Tuning means editing data.

    Stage 1  WEIGHTS     every finding is mapped to a signal TYPE (TYPE_RULES);
                         each distinct type adds its weight once, however many
                         times it repeats ("how sure am I from this alone")
    Stage 2  COMBOS      bonus when ALL listed types/groups are present
                         (weak signals together = strong signal)
    Stage 3  DAMPENERS   false-alarm control: (reason, condition, type, delta)
    Stage 4  CAP+BANDS   clamp to 0..100, then THRESHOLDS -> safe/suspicious/malicious
                         (thresholds come from `python -m harmonica calibrate`)
    Stage 5  OVERRIDE    any finding with severity "malicious" forces band
                         "malicious"; arithmetic never downgrades a confirmed payload

The explanation is a list of human-readable lines, one per point change, so
the UI can show exactly why a package got its score.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .profile import build_profile
from .scanner import Finding

# ============================================================================
# CONFIG: edit these, not the logic
# ============================================================================

# Stage 4: set by `python -m harmonica calibrate` (2026-10-31: 4 malicious samples,
# 709 benign packages incl. 707 real-code corpus units; highest benign score 35,
# lowest malicious 100). Re-run calibrate after changing any weight.
THRESHOLDS = {"malicious": 45, "suspicious": 24}

# Stage 1: how sure we are from one signal type alone (0..100)
WEIGHTS = {
    # named attacks: proof on their own
    "glassworm_unicode": 100,    # invisible-Unicode payload that decodes to code
    "trojan_source_bidi": 100,   # bidi controls reordering code (CVE-2021-42574)
    "stego_payload": 90,         # code / executable hidden in or disguised as an image
    # payload execution
    "eval_decoded": 40,          # exec(b64decode(...)), eval(atob(...))
    "dynamic_fetch": 40,         # exec(urlopen()), .then(eval), curl | sh with spawn
    "stealer_shape": 40,         # secrets + exfil endpoint in one file (code_scan)
    "stego_loader": 35,          # loads image data then evals
    "glassworm_loader": 30,      # 0xFE00/0xE0100 arithmetic next to eval
    "glassworm_dense": 30,       # long undecodable invisible run in code
    "stego_metadata_code": 30,
    # exfiltration
    "webhook_exfil": 40,         # Discord / Telegram webhook
    "exfil_host": 25,            # paste / tunnel / request-catcher host
    "raw_ip_url": 15,
    # credentials
    "ssh_aws_read": 35,
    "credential_path": 25,       # browser stores, wallets, registry tokens, kube/docker
    "env_dump": 25,              # JSON.stringify(process.env)
    "env_read": 10,              # secret-looking env var by name
    "secret_and_network": 15,    # credential read + network in one small file
    "dotenv_read": 3,
    "env_enum": 3,
    # identity / metadata (Aryan's checks + meta-derived)
    "typosquat": 25,
    "new_package": 5,
    "low_downloads": 5,
    "maintainer_change": 15,
    "no_repo": 5,
    # code shape
    "invisible_identifier": 25,
    "glassworm_hidden_text": 20,
    "encoded_code": 25,          # base64/hex string that decodes to code
    "obfuscation": 15,           # string-name lookups, split literals, _0x names, chr chains
    "dynamic_fetch_weak": 15,    # network call near eval, or both in one small file
    "stego_anomaly": 15,
    "hook_exists": 5,
    "network_call": 10,
    "dynamic_exec": 10,          # eval/exec on a computed value
    "process_spawn": 10,
    "svg_script": 10,
    # noise: recorded as evidence, scored as nothing
    "stray_invisible": 0, "hidden_watermark": 0, "opaque_blob": 0, "shell_mention": 0,
    "media_trailer": 0, "literal_exec": 0, "ignore": 0,
}

# Stage 1: finding -> type. First match wins. (check, message regex or None, type).
# Matches the messages the scanner actually emits; checks are never renamed.
TYPE_RULES = [
    ("trojan_source_bidi", None, "trojan_source_bidi"),
    ("glassworm", r"^Hidden payload", "glassworm_unicode"),
    ("glassworm", r"^Invisible-Unicode decoder", "glassworm_loader"),
    ("glassworm", r"^Dense run .* that ", "glassworm_dense"),
    ("glassworm", r"^Hidden (code in a non-code file|text:)", "glassworm_hidden_text"),
    ("glassworm", r"Invisible identifier|inside an identifier", "invisible_identifier"),
    ("glassworm", r"possible watermark|non-code file", "hidden_watermark"),
    ("glassworm", None, "stray_invisible"),
    ("stego", r"hidden after the|is not an image|executable .* appended", "stego_payload"),
    ("stego", r"^Image-stego loader", "stego_loader"),
    ("stego", r"^Code in .* metadata", "stego_metadata_code"),
    ("stego", r"^SVG image", "svg_script"),
    ("stego", r"^Second media stream|bytes of text after", "media_trailer"),
    ("stego", None, "stego_anomaly"),
    ("obfuscation", r"^Decodes (an encoded string and executes|and executes hidden code)", "eval_decoded"),
    ("obfuscation", r"string decodes to code", "encoded_code"),
    ("obfuscation", r"large opaque string", "opaque_blob"),
    ("obfuscation", None, "obfuscation"),
    ("dynamic_fetch", r"^(Downloads code and executes|Response of a network request|Shell command downloads)",
     "dynamic_fetch"),
    ("dynamic_fetch", r"^Mentions a download-and-run", "shell_mention"),
    ("dynamic_fetch", None, "dynamic_fetch_weak"),
    ("network_exfil", r"Discord webhook|Telegram bot", "webhook_exfil"),
    ("network_exfil", r"paste / tunnel", "exfil_host"),
    ("network_exfil", r"raw public IP", "raw_ip_url"),
    ("network_exfil", r"AND contains an exfiltration endpoint", "stealer_shape"),
    ("network_exfil", None, "secret_and_network"),
    ("credential_access", r"^References credential locations:.*(SSH keys|AWS credentials)", "ssh_aws_read"),
    ("credential_access", r"^References credential locations:.*(browser|wallets|registry|Docker|history)",
     "credential_path"),
    ("credential_access", r"^References credential locations", "dotenv_read"),
    ("credential_access", r"secret-looking environment", "env_read"),
    ("credential_access", r"entire environment", "env_dump"),
    ("credential_access", r"Enumerates every environment", "env_enum"),
    ("dangerous_call", r"of a literal string", "literal_exec"),
    ("dangerous_call", r"Spawns a process|Runs a system command", "process_spawn"),
    ("dangerous_call", None, "dynamic_exec"),
    ("capability", r"^network:", "network_call"),
    ("capability", None, "ignore"),
    ("install_hooks", None, "hook_exists"),
    ("typosquat", None, "typosquat"),
    ("metadata", r"(?i)maintainer", "maintainer_change"),
    ("metadata", r"(?i)download", "low_downloads"),
    ("metadata", r"(?i)repo", "no_repo"),
    ("metadata", r"(?i)new|recent|publish", "new_package"),
]

# Stage 1b: class caps. Capabilities are what ordinary software does (pip reads
# ~/.netrc, spawns processes and uses the network); on their own they are not
# intent. Together they may add at most CLASS_CAPS[class], which equals the
# strongest single capability, so each anchor still counts in full when alone.
# Attack signals and combos are never capped.
TYPE_CLASS = {t: "capability" for t in (
    "ssh_aws_read", "credential_path", "env_dump", "env_read", "env_enum", "dotenv_read",
    "secret_and_network", "process_spawn", "dynamic_exec", "network_call", "dynamic_fetch_weak",
    "hook_exists", "svg_script",
)}
CLASS_CAPS = {"capability": 35}

# Combos can name a type or a group of types
GROUPS = {
    "obfuscation": {"obfuscation", "encoded_code"},
    "dynamic_fetch": {"dynamic_fetch", "dynamic_fetch_weak"},
    "webhook_exfil": {"webhook_exfil", "exfil_host", "stealer_shape"},
    "ssh_aws_read": {"ssh_aws_read", "credential_path", "env_dump"},
}

# Stage 2: (required types/groups, bonus, reason)
COMBOS = [
    ({"hook_exists", "ssh_aws_read", "webhook_exfil"}, 40, "credential stealer in installer"),
    ({"eval_decoded", "obfuscation"}, 30, "obfuscated payload execution"),
    ({"typosquat", "new_package", "low_downloads"}, 30, "typosquat with no legitimacy"),
    ({"dynamic_fetch", "hook_exists"}, 25, "downloads and runs code at install"),
]

# Version-diff (diff.py): risky signal types that FIRST appear in a patch or minor
# release get a bonus. Hijacked updates ship as innocent-looking patch bumps.
# "new_install_script" and "new_dependency" are synthesized by diff.py itself.
UPDATE_RISK_TYPES = {
    "glassworm_unicode", "trojan_source_bidi", "stego_payload", "stego_loader", "glassworm_loader",
    "eval_decoded", "dynamic_fetch", "stealer_shape", "webhook_exfil", "exfil_host", "raw_ip_url",
    "ssh_aws_read", "credential_path", "env_dump", "encoded_code", "obfuscation",
    "hook_exists", "new_install_script",
}
UPDATE_RISK_BONUS = {"patch": 20, "minor": 10}  # major bumps are expected to change behaviour

# Meta-derived signals (used when Aryan's metadata check hasn't emitted them)
NEW_PACKAGE_DAYS = 30
LOW_DOWNLOADS = 1_000
POPULAR_DOWNLOADS = 100_000

# Packages whose stated purpose involves the network: matched against name,
# keywords, description and (if the resolver provides it) a "category" field
NETWORK_PURPOSE = {"http", "https", "fetch", "request", "requests", "client", "api", "sdk", "websocket",
                   "socket", "proxy", "download", "upload", "image", "images", "cdn", "cloud", "aws",
                   "s3", "graphql", "rpc", "net", "network", "mail", "smtp", "oauth", "webhook", "server"}
NETWORK_DEPS = {"axios", "node-fetch", "got", "undici", "superagent", "request", "needle", "ws",
                "requests", "httpx", "aiohttp", "urllib3", "httplib2", "boto3"}
EXFIL_TYPES = {"webhook_exfil", "exfil_host", "raw_ip_url", "stealer_shape", "secret_and_network"}


def _needs_network(meta: dict, types: set[str]) -> bool:
    text = " ".join(str(meta.get(k) or "") for k in ("name", "category", "description"))
    text += " " + " ".join(meta.get("keywords") or [])
    words = set(re.split(r"[^a-z0-9]+", text.lower()))
    deps = set(meta.get("dependencies") or [])
    return bool(words & NETWORK_PURPOSE or deps & NETWORK_DEPS) and not types & EXFIL_TYPES


# Stage 3: (reason, condition(meta, types), type it applies to, delta)
DAMPENERS = [
    ("popular package (>100k downloads) is not a typosquat",
     lambda meta, types: (meta.get("downloads") or 0) > POPULAR_DOWNLOADS,
     "typosquat", -WEIGHTS["typosquat"]),
    ("network access fits the package's stated purpose",
     _needs_network,
     "network_call", -WEIGHTS["network_call"]),
]

# ============================================================================
# logic
# ============================================================================

_COMPILED = [(check, re.compile(rx) if rx else None, t) for check, rx, t in TYPE_RULES]


def finding_type(f: Finding) -> str:
    for check, rx, t in _COMPILED:
        if f.check == check and (rx is None or rx.search(f.message)):
            return t
    return f.check  # unknown check: scored by its own Finding.weight (see _weight)


def _weight(t: str, findings: list[Finding]) -> int:
    return WEIGHTS[t] if t in WEIGHTS else max(f.weight for f in findings)


def _meta_types(meta: dict) -> dict[str, str]:
    out = {}
    downloads = meta.get("downloads")
    if isinstance(downloads, int) and downloads < LOW_DOWNLOADS:
        out["low_downloads"] = f"only {downloads} downloads"
    published = meta.get("published")
    if published:
        try:
            when = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - when).days
            if age < NEW_PACKAGE_DAYS:
                out["new_package"] = f"published {age} day(s) ago"
        except ValueError:
            pass
    return out


def band_for(score: int) -> str:
    if score >= THRESHOLDS["malicious"]:
        return "malicious"
    return "suspicious" if score >= THRESHOLDS["suspicious"] else "safe"


def _has(req: str, types: set[str]) -> bool:
    return bool(GROUPS.get(req, {req}) & types)


def score(findings: list[Finding], meta: dict | None = None) -> tuple[int, str, list[str]]:
    meta = meta or {}
    explanation: list[str] = []

    # Stage 1: one weight per distinct type
    by_type: dict[str, list[Finding]] = {}
    for f in findings:
        by_type.setdefault(finding_type(f), []).append(f)
    total = 0
    class_sums: dict[str, int] = {}
    for t, fs in sorted(by_type.items(), key=lambda kv: -_weight(kv[0], kv[1])):
        w = _weight(t, fs)
        if w <= 0:
            continue
        first = fs[0]
        more = f" (+{len(fs) - 1} more)" if len(fs) > 1 else ""
        explanation.append(f"+{w} {t}: {first.message[:110]} [{first.location}]{more}")
        total += w
        if t in TYPE_CLASS:
            class_sums[TYPE_CLASS[t]] = class_sums.get(TYPE_CLASS[t], 0) + w
    for cls, used in class_sums.items():
        cap = CLASS_CAPS.get(cls)
        if cap is not None and used > cap:
            explanation.append(f"-{used - cap} cap: {cls} signals add at most {cap} together "
                               f"(they sum to {used}; capability alone is not intent)")
            total -= used - cap
    for t, why in _meta_types(meta).items():
        if t not in by_type:
            by_type[t] = []
            explanation.append(f"+{WEIGHTS[t]} {t}: {why} [registry metadata]")
            total += WEIGHTS[t]
    types = set(by_type)

    # Stage 2: combos
    for required, bonus, reason in COMBOS:
        if all(_has(r, types) for r in required):
            explanation.append(f"+{bonus} combo: {reason} ({' + '.join(sorted(required))})")
            total += bonus

    # Stage 3: dampeners
    for reason, condition, t, delta in DAMPENERS:
        if t in types and condition(meta, types):
            explanation.append(f"{delta:+d} dampener: {reason} ({t})")
            total += delta

    # Stage 4: cap + bands
    capped = max(0, min(100, total))
    if capped != total:
        explanation.append(f"= {capped} (clamped from {total})")
    band = band_for(capped)

    # Stage 5: severity override
    confirmed = next((f for f in findings if f.severity == "malicious"), None)
    if confirmed and band != "malicious":
        explanation.append(f"band forced to malicious by a confirmed finding: {confirmed.check} "
                           f"[{confirmed.location}]")
        band = "malicious"
        capped = max(capped, THRESHOLDS["malicious"])
    return capped, band, explanation


def build_verdict(pkg: str | dict, findings: list[Finding]) -> dict:
    """`pkg` is the package name, or the meta dict from resolve()."""
    meta = pkg if isinstance(pkg, dict) else {"name": pkg}
    total, band, explanation = score(findings, meta)
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
        "explanation": explanation,  # additive: per-line score breakdown for the UI
    }
