"""GlassWorm detector: payloads hidden in invisible Unicode.

GlassWorm-style attacks hide code in codepoints that editors, diff viewers and
code review tools render as nothing. A string that looks like ``""`` can carry
kilobytes of JavaScript, and a short visible loader decodes and ``eval``s it.

This check runs on RAW BYTES, before anything tokenizes or normalizes the text:

1. Find runs of invisible codepoints (variation selectors, tag characters,
   zero-width chars, private-use, bidi controls, invisible identifier fillers).
2. Skip runs that are legitimate Unicode: emoji presentation selectors, emoji
   ZWJ sequences, subdivision flags, CJK ideographic variants, Indic/Persian
   joiners, icon-font glyphs. A tool that flags every emoji is useless.
3. Try to DECODE each remaining run with the known smuggling schemes and judge
   what comes out: readable code, readable text, or opaque bytes.
4. Rescan any recovered code with code_scan, so the hidden payload is analyzed
   like any other source.
5. Separately, flag the visible half of the attack: a decoder that does
   variation-selector arithmetic (0xFE00 / 0xE0100) near eval/Function.

reveal() returns the same hits as structured data for the UI's
"invisible -> visible" panel.
"""

from __future__ import annotations

import bisect
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from . import code_scan
from .scanner import Finding, iter_files, rel

CHECK = "glassworm"
TROJAN_SOURCE = "trojan_source_bidi"

# --- codepoint classes ------------------------------------------------------

ZWSP, ZWNJ, ZWJ, BOM = 0x200B, 0x200C, 0x200D, 0xFEFF
ZERO_WIDTH = {ZWSP, ZWNJ, ZWJ, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, BOM, 0x180E}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # Trojan Source
FILLERS = {0x3164, 0xFFA0, 0x115F, 0x1160}  # Hangul fillers: render blank, valid in identifiers

HIDDEN_RUN = re.compile(
    "["
    "​-‍⁠-⁤﻿᠎"  # zero-width
    "‪-‮⁦-⁩"  # bidi controls
    "︀-️\U000e0100-\U000e01ef"  # variation selectors
    "\U000e0000-\U000e007f"  # tag characters
    "-\U000f0000-\U0010ffff"  # private use
    "ㅤﾠᅟᅠ"  # fillers
    "]+"
)


def _is_vs(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_pua(cp: int) -> bool:
    return 0xE000 <= cp <= 0xF8FF or cp >= 0xF0000


def _kind(cp: int) -> str:
    if _is_vs(cp):
        return "variation-selector"
    if _is_tag(cp):
        return "tag"
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in BIDI:
        return "bidi-control"
    if cp in FILLERS:
        return "invisible-filler"
    return "private-use"


# --- file classification ----------------------------------------------------

CODE_EXT = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte",
    ".coffee", ".json", ".html", ".htm", ".py", ".pyw", ".pyi", ".pth", ".sh",
    ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".rb", ".php",
    ".pl", ".lua", ".go", ".rs", ".java", ".kt", ".cs", ".c", ".h", ".cpp", ".gyp",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".wasm",
    ".node", ".so", ".dll", ".dylib", ".exe", ".pyc", ".pyo", ".whl", ".pdf",
}


def _is_code_file(path: Path, data: bytes) -> bool:
    return path.suffix.lower() in CODE_EXT or path.name in {"Makefile", "Dockerfile"} \
        or data.startswith(b"#!")


# --- decoding ---------------------------------------------------------------

CODE_TOKENS = re.compile(
    r"require\s*\(|\bimport\s|\beval\s*\(|Function\s*\(|\bexec\w*\s*\(|child_process"
    r"|subprocess|os\.system|__import__|process\.env|=>|\bfunction\b|\b(?:const|let|var)\s"
    r"|https?://|Buffer\.from|\batob\s*\(|fetch\s*\(|\bdef\s+\w+\s*\(|console\.\w+\s*\("
)


def _bytes_to_text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\n\r\t" for ch in s) / len(s)


def _readable(s: str | None) -> bool:
    return bool(s) and len(s.strip()) >= 4 and _printable_ratio(s) >= 0.9


def _looks_like_code(s: str) -> bool:
    return bool(CODE_TOKENS.search(s))


def _try_decode(cps: list[int]) -> tuple[str | None, int, str | None]:
    """Try the known smuggling schemes. Returns (text|None, n_bytes, scheme)."""
    n = len(cps)

    # Variation selectors as bytes (GlassWorm / "emoji smuggling"):
    # U+FE00..FE0F -> 0..15, U+E0100..E01EF -> 16..255
    vs = [c for c in cps if _is_vs(c)]
    if len(vs) >= 2 and len(vs) >= 0.8 * n:
        data = bytes(c - 0xFE00 if c <= 0xFE0F else c - 0xE0100 + 16 for c in vs)
        return _bytes_to_text(data), len(data), "variation selectors as bytes"

    # Tag characters as ASCII ("ASCII smuggling"): U+E0020..E007E -> ' '..'~'
    tags = [c for c in cps if _is_tag(c)]
    if len(tags) >= 2 and len(tags) >= 0.8 * n:
        text = "".join(chr(c - 0xE0000) for c in tags if 0xE0020 <= c <= 0xE007E)
        return text, len(text), "tag characters as ASCII"

    # Two zero-width symbols as binary, 8 bits per byte. Try both bit polarities.
    if n >= 16 and all(c in ZERO_WIDTH for c in cps) and len(set(cps)) == 2:
        best: str | None = None
        for one in set(cps):
            bits = "".join("1" if c == one else "0" for c in cps)
            data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
            text = _bytes_to_text(data)
            if text is not None and (best is None or _printable_ratio(text) > _printable_ratio(best)):
                best = text
        return best, n // 8, "zero-width binary"

    # Private-use low byte: U+E000..E0FF -> 0..255
    if n >= 4 and all(0xE000 <= c <= 0xE0FF for c in cps):
        data = bytes(c - 0xE000 for c in cps)
        return _bytes_to_text(data), len(data), "private-use as bytes"

    return None, 0, None


# --- legitimate-use filter --------------------------------------------------


def _is_benign(cps: list[int], prev: str, nxt: str, start: int, is_code: bool) -> bool:
    n = len(cps)
    if start == 0 and cps == [BOM]:
        return True  # byte-order mark
    # Emoji presentation (U+FE0F) / CJK ideographic variant (U+E01xx) attached to
    # a visible char, optionally followed by a ZWJ in an emoji sequence: ❤️ 🏳️‍🌈 葛󠄀
    if prev and not prev.isspace() and n <= 2 and _is_vs(cps[0]) and (n == 1 or cps[1] == ZWJ):
        return True
    # ZWJ/ZWNJ joining two non-ASCII chars: emoji families, Devanagari, Persian
    if n == 1 and cps[0] in (ZWJ, ZWNJ) and prev and nxt and ord(prev) > 0x7F and ord(nxt) > 0x7F:
        return True
    # Subdivision flags: 🏴 + tag letters + CANCEL TAG (England, Scotland, Wales)
    if prev == "\U0001F3F4" and n <= 8 and cps[-1] == 0xE007F and all(0xE0020 <= c <= 0xE007F for c in cps):
        return True
    # Icon-font glyphs ("" written literally in CSS/JS) come one or two at a time
    if n < 4 and all(_is_pua(c) for c in cps):
        return True
    # Bidi controls only change meaning where code gets parsed (RTL prose is fine)
    if not is_code and all(c in BIDI for c in cps):
        return True
    return False


# --- scanning ---------------------------------------------------------------


@dataclass
class Hit:
    path: str
    line: int
    col: int
    offset: int  # character offset in the decoded text
    length: int  # number of hidden codepoints in the run
    kinds: dict[str, int]
    in_empty_string: bool
    in_identifier: bool
    scheme: str | None
    decoded: str | None  # recovered text, if a scheme produced readable output
    decoded_bytes: int
    preview: str  # the source line with the run made visible

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}:{self.col}"

    def to_dict(self) -> dict:
        return {**asdict(self), "location": self.location}


def _visible(s: str, limit: int = 120) -> str:
    """Escape anything non-printable so messages are safe to print anywhere."""
    out = []
    for ch in s:
        if ch.isprintable() and not HIDDEN_RUN.match(ch):
            out.append(ch)
        elif ch == "\n":
            out.append("\\n")
        else:
            out.append(f"\\u{{{ord(ch):X}}}")
    text = "".join(out)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _preview_line(text: str, line_start: int, start: int, end: int, kinds: Counter) -> str:
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    before = text[max(line_start, start - 60):start]
    after = text[end:min(line_end, end + 60)]
    label = "+".join(sorted(kinds))
    marker = f"⟦{end - start} hidden {label}⟧"
    return _visible(before, 80) + marker + _visible(after, 80)


def scan_text(text: str, path: str, is_code: bool) -> list[Hit]:
    hits: list[Hit] = []
    line_starts: list[int] | None = None
    for m in HIDDEN_RUN.finditer(text):
        start, end = m.span()
        cps = [ord(c) for c in m.group()]
        prev = text[start - 1] if start > 0 else ""
        nxt = text[end] if end < len(text) else ""
        if _is_benign(cps, prev, nxt, start, is_code):
            continue

        if line_starts is None:
            line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
        idx = bisect.bisect_right(line_starts, start) - 1
        kinds = Counter(_kind(c) for c in cps)
        decoded, n_bytes, scheme = _try_decode(cps)
        hits.append(Hit(
            path=path,
            line=idx + 1,
            col=start - line_starts[idx] + 1,
            offset=start,
            length=len(cps),
            kinds=dict(kinds),
            in_empty_string=prev in "\"'`" and prev != "" and nxt == prev,
            in_identifier=(prev.isalnum() or prev == "_") and (nxt.isalnum() or nxt == "_"),
            scheme=scheme,
            decoded=decoded if _readable(decoded) else None,
            decoded_bytes=n_bytes,
            preview=_preview_line(text, line_starts[idx], start, end, kinds),
        ))
    return hits


# The visible half of the attack: variation-selector / tag arithmetic near a sink.
DECODER_CONST = re.compile(r"0x[eE]0100\b|\b917760\b|0x[fF][eE]00\b|\b65024\b|0x[eE]0000\b|\b917504\b")
EVAL_SINK = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(|\bexec\s*\(|vm\.run\w*\s*\("
)
BENIGN_SINK = re.compile(r"""Function\s*\(\s*(["'])return this\1\s*\)""")  # globalThis polyfill
DECODER_WINDOW = 1500  # chars; minified bundles put everything on one line


def _decoder_tell(text: str, path: str) -> Finding | None:
    consts = [m.start() for m in DECODER_CONST.finditer(text)]
    if not consts:
        return None
    cleaned = BENIGN_SINK.sub(lambda m: " " * len(m.group()), text)
    for sink in EVAL_SINK.finditer(cleaned):
        i = bisect.bisect_left(consts, sink.start() - DECODER_WINDOW)
        if i < len(consts) and consts[i] <= sink.start() + DECODER_WINDOW:
            line = text.count("\n", 0, sink.start()) + 1
            return Finding(
                check=CHECK,
                severity="suspicious",
                weight=30,
                message=(
                    "Invisible-Unicode decoder: variation-selector/tag codepoint arithmetic "
                    f"next to `{sink.group().strip()}`, the visible half of a GlassWorm loader"
                ),
                location=f"{path}:{line}",
            )
    return None


# --- hits -> findings -------------------------------------------------------

MAX_PAYLOAD_FINDINGS_PER_FILE = 10


def _hit_finding(hit: Hit, is_code: bool) -> Finding | None:
    """Turn one hit into a Finding, or None if it's minor (aggregated later)."""
    kinds = ", ".join(sorted(hit.kinds))
    where = " inside a string that looks empty" if hit.in_empty_string else ""
    bonus = 10 if hit.in_empty_string else 0

    if hit.decoded is not None:
        shown = _visible(hit.decoded, 100)
        if _looks_like_code(hit.decoded):
            if is_code:
                return Finding(CHECK, "malicious", 70 + bonus,
                               f"Hidden payload: {hit.length} invisible {kinds} codepoints{where} "
                               f"decode ({hit.scheme}) to code: `{shown}`", hit.location)
            return Finding(CHECK, "suspicious", 30,
                           f"Hidden code in a non-code file: {hit.length} invisible {kinds} "
                           f"codepoints decode ({hit.scheme}) to: `{shown}`", hit.location)
        if is_code:
            return Finding(CHECK, "suspicious", 20 + bonus,
                           f"Hidden text: {hit.length} invisible {kinds} codepoints{where} "
                           f"decode ({hit.scheme}) to: `{shown}`", hit.location)
        return Finding(CHECK, "info", 5,
                       f"Hidden text (possible watermark): {hit.length} invisible {kinds} "
                       f"codepoints decode ({hit.scheme}) to: `{shown}`", hit.location)

    if hit.length >= 16:
        what = (f"decode to {hit.decoded_bytes} bytes of binary data (encrypted or compressed?)"
                if hit.scheme else "match no known encoding")
        if is_code:
            return Finding(CHECK, "suspicious", 35 + bonus,
                           f"Dense run of {hit.length} invisible {kinds} codepoints{where} "
                           f"that {what}", hit.location)
        return Finding(CHECK, "info", 5,
                       f"Dense run of {hit.length} invisible {kinds} codepoints in a non-code file",
                       hit.location)

    if not is_code:
        return None
    if "invisible-filler" in hit.kinds:
        return Finding(CHECK, "suspicious", 25,
                       "Invisible identifier character (Hangul filler): renders as blank but is "
                       "a valid identifier, a known way to hide a backdoor parameter", hit.location)
    if set(hit.kinds) == {"bidi-control"}:
        # Its own named threat, not a GlassWorm sub-case: same raw-byte pass, separate check.
        return Finding(TROJAN_SOURCE, "malicious", 100,
                       f"Trojan Source (CVE-2021-42574): {hit.length} bidirectional control character(s) "
                       "in code reorder how it displays vs. how it executes", hit.location)
    if hit.in_identifier:
        return Finding(CHECK, "suspicious", 15,
                       f"{hit.length} invisible {kinds} character(s) inside an identifier: two names "
                       "that look identical are actually different", hit.location)
    return None


def _mask_literals(hits: list[Hit], text: str, path: Path) -> None:
    """An invisible char between letters is only an identifier trick in CODE.
    Inside a string literal or comment (code-page tables, JSON, Unicode test
    data) it is data, so clear in_identifier and drop lone fillers there."""
    if not any(h.in_identifier or "invisible-filler" in h.kinds for h in hits):
        return
    # The invisible-identifier attack is documented for JS/TS/Python, where we can also
    # tell code from string literals. Anywhere else, treat these chars as data.
    lexable = path.suffix.lower() in code_scan.JS_EXT | code_scan.PY_EXT
    blanked = code_scan.js_lex(text)[0] if lexable else ""  # py quoting is close enough
    keep = []
    for h in hits:
        in_literal = not lexable or blanked[h.offset] != text[h.offset]
        if in_literal:
            h.in_identifier = False
            if set(h.kinds) == {"invisible-filler"} and h.decoded is None and h.length < 16:
                continue
        keep.append(h)
    hits[:] = keep


def _read_text(path: Path) -> tuple[bytes, str] | None:
    """Raw bytes + lossless str view, or None for binaries."""
    if path.suffix.lower() in BINARY_EXT:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data, data.decode("utf-8", errors="surrogateescape")


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    pkg_dir = Path(pkg_dir)
    findings: list[Finding] = []
    for path in iter_files(pkg_dir):
        read = _read_text(path)
        if not read:
            continue
        data, text = read
        relpath = rel(path, pkg_dir)
        is_code = _is_code_file(path, data)

        # the decoder is usually plain ASCII, so look for it before the ASCII shortcut
        if is_code and (tell := _decoder_tell(text, relpath)):
            findings.append(tell)
        if data.isascii():
            continue  # pure ASCII can't hide anything
        hits = scan_text(text, relpath, is_code)
        _mask_literals(hits, text, path)

        payloads, minor = [], []
        for hit in hits:
            f = _hit_finding(hit, is_code)
            (payloads if f else minor).append((hit, f))

        for hit, f in payloads[:MAX_PAYLOAD_FINDINGS_PER_FILE]:
            findings.append(f)
            # The recovered code is source like any other: run the code detectors on it
            if hit.decoded is not None and f.severity == "malicious":
                for sub in code_scan.scan_source(
                        hit.decoded, origin=f"{hit.location} (decoded payload)", line_numbers=False):
                    sub.message = f"[inside hidden payload] {sub.message}"
                    findings.append(sub)
        if len(payloads) > MAX_PAYLOAD_FINDINGS_PER_FILE:
            extra = payloads[MAX_PAYLOAD_FINDINGS_PER_FILE:]
            findings.append(Finding(CHECK, "info", 0,
                                    f"…and {len(extra)} more invisible-Unicode hits in this file",
                                    extra[0][0].location))
        if minor and is_code:
            total = sum(h.length for h, _ in minor)
            findings.append(Finding(CHECK, "info", 2,
                                    f"{total} stray invisible character(s) in {len(minor)} place(s) "
                                    "(often copy-paste residue)", minor[0][0].location))
    return findings


def reveal(pkg_dir: Path | str) -> list[dict]:
    """Every non-benign invisible-Unicode hit, decoded, for the UI reveal panel."""
    pkg_dir = Path(pkg_dir)
    out = []
    for path in iter_files(pkg_dir):
        read = _read_text(path)
        if read and not read[0].isascii():
            hits = scan_text(read[1], rel(path, pkg_dir), _is_code_file(path, read[0]))
            out.extend(h.to_dict() for h in hits)
    return out
