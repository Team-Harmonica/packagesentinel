"""Steganography red flags (scanner group I, raw bytes).

We don't try to *solve* steganography; we flag the patterns real loaders use:

1. Data appended after the image's end marker (PNG IEND, JPEG EOI, GIF
   trailer). Image viewers stop at the marker, so anything after it is
   invisible, and a loader can slice it off and run it. If the appended bytes
   decode to code, they are rescanned with code_scan.
2. Code hidden in image metadata (PNG tEXt/zTXt/iTXt chunks, JPEG comments).
3. Files that only pretend to be images (`logo.png` that is really JS or an
   ELF binary), SVGs with embedded scripts, and uncompressed images whose
   pixels look like noise (abnormally high entropy).
4. The visible half: a code file that loads image data (image library, image
   file path, or the IEND / FFD9 markers themselves) AND runs dynamic code,
   optionally after downloading something.

Images are parsed with struct/zlib only; nothing is rendered or decoded beyond
the container structure, and decompression is size-capped.
"""

from __future__ import annotations

import ast
import base64
import binascii
import math
import re
import struct
import warnings
import zlib
from collections import Counter
from pathlib import Path

from . import code_scan
from .scanner import Finding, iter_files, rel

CHECK = "stego"

PNG_SIG = b"\x89PNG\r\n\x1a\n"
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff"}
MAX_INFLATE = 1_000_000  # cap on zTXt / gzip decompression (zip-bomb guard)
MIN_TRAILER = 16  # some encoders leave a stray newline or a few padding bytes

# metadata is full of URLs (XMP namespaces) and prose, so require execution-ish tokens
STRICT_CODE = re.compile(
    r"\beval\s*\(|Function\s*\(|require\s*\(|\bimport\s+\w|\bexec\w*\s*\(|child_process|subprocess"
    r"|os\.system|__import__|powershell|<script\b|\bfunction\s*\w*\s*\(|=>\s*\{"
)
XMP_KEYS = ("XML:com.adobe.xmp", "Raw profile type", "icc")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:1_000_000]
    n = len(sample)
    return -sum(c / n * math.log2(c / n) for c in Counter(sample).values())


def _readable(text: str) -> bool:
    return len(text.strip()) >= 8 and sum(c.isprintable() or c in "\n\r\t" for c in text) / len(text) >= 0.9


def _preview(text: str, limit: int = 90) -> str:
    text = "".join(c if c.isprintable() else " " for c in text.strip())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- container parsers: return (offset where the image ends | None, [(label, text)]) ---


def _inflate(data: bytes) -> bytes:
    try:
        return zlib.decompressobj().decompress(data, MAX_INFLATE)
    except zlib.error:
        return b""


def parse_png(data: bytes) -> tuple[int | None, list[tuple[str, str]]]:
    pos, texts = len(PNG_SIG), []
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if pos + 12 + length > len(data):
            return None, texts  # truncated
        if ctype == b"IEND":
            return pos + 12 + length, texts
        try:
            if ctype == b"tEXt":
                key, _, val = body.partition(b"\0")
                texts.append((key.decode("latin-1"), val.decode("latin-1")))
            elif ctype == b"zTXt":
                key, _, rest = body.partition(b"\0")
                texts.append((key.decode("latin-1"), _inflate(rest[1:]).decode("latin-1")))
            elif ctype == b"iTXt":
                key, _, rest = body.partition(b"\0")
                compressed, rest = rest[0], rest[2:]
                _lang, _, rest = rest.partition(b"\0")
                _tkey, _, val = rest.partition(b"\0")
                val = _inflate(val) if compressed else val
                texts.append((key.decode("latin-1"), val.decode("utf-8", errors="replace")))
        except IndexError:
            pass
        pos += 12 + length
    return None, texts


def parse_jpeg(data: bytes) -> tuple[int | None, list[tuple[str, str]]]:
    pos, texts = 2, []
    while pos + 2 <= len(data):
        if data[pos] != 0xFF:
            return None, texts
        marker = data[pos + 1]
        if marker == 0xFF:  # fill byte
            pos += 1
            continue
        if marker == 0xD9:
            return pos + 2, texts
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if pos + 4 > len(data):
            return None, texts
        seglen = int.from_bytes(data[pos + 2:pos + 4], "big")
        if marker == 0xFE:
            texts.append(("COM", data[pos + 4:pos + 2 + seglen].decode("latin-1")))
        pos += 2 + seglen
        if marker == 0xDA:  # start of scan: skip entropy-coded data up to the next real marker
            while True:
                pos = data.find(b"\xff", pos)
                if pos == -1 or pos + 1 >= len(data):
                    return None, texts
                nxt = data[pos + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    pos += 1 if nxt == 0xFF else 2
                    continue
                break
    return None, texts


def parse_gif(data: bytes) -> tuple[int | None, list[tuple[str, str]]]:
    def skip_subblocks(p: int) -> tuple[int, bytes]:
        out = bytearray()
        while p < len(data):
            size = data[p]
            if size == 0:
                return p + 1, bytes(out)
            out += data[p + 1:p + 1 + size]
            p += 1 + size
        raise IndexError

    texts: list[tuple[str, str]] = []
    try:
        flags = data[10]
        pos = 13 + (3 * 2 ** ((flags & 7) + 1) if flags & 0x80 else 0)
        while pos < len(data):
            block = data[pos]
            if block == 0x3B:
                return pos + 1, texts
            if block == 0x21:  # extension
                label = data[pos + 1]
                pos, body = skip_subblocks(pos + 2)
                if label == 0xFE:
                    texts.append(("comment", body.decode("latin-1")))
            elif block == 0x2C:  # image descriptor
                lflags = data[pos + 9]
                pos += 10 + (3 * 2 ** ((lflags & 7) + 1) if lflags & 0x80 else 0)
                pos, _ = skip_subblocks(pos + 1)  # +1 skips LZW minimum code size
            else:
                return None, texts
    except IndexError:
        pass
    return None, texts


def image_format(data: bytes) -> str | None:
    if data.startswith(PNG_SIG):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if data.startswith(b"BM"):
        return "BMP"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    if data[:4] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"):
        return "ICO"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    return None


PARSERS = {"PNG": (parse_png, "IEND chunk"), "JPEG": (parse_jpeg, "JPEG end marker"),
           "GIF": (parse_gif, "GIF trailer")}


# --- what is this blob? ---------------------------------------------------------


def _code_in(blob: bytes) -> str | None:
    """Readable code inside raw bytes, directly or base64-wrapped."""
    text = blob.decode("utf-8", errors="replace")
    if not _readable(text):
        return None
    if code_scan.CODE_TOKENS.search(text):
        return text
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 40 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            inner = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
        if _readable(inner) and code_scan.CODE_TOKENS.search(inner):
            return inner
    return None


def _classify(blob: bytes) -> tuple[str, str | None]:
    """(kind, code-text-if-any). kinds: code, executable, archive, compressed,
    media, text, opaque."""
    if b"ftyp" in blob[4:16]:
        return "embedded media", None  # motion photo: an MP4 appended to the JPEG
    head = blob.lstrip(b"\x00\r\n\t ")[:4096]
    if head.startswith(b"\x7fELF"):
        return "ELF executable", None
    if head.startswith(b"MZ") and b"This program cannot be run" in head[:1024]:
        return "Windows executable", None
    if head.startswith(b"\xcf\xfa\xed\xfe") or head.startswith(b"\xca\xfe\xba\xbe"):
        return "Mach-O executable", None
    if head.startswith(b"PK\x03\x04"):
        return "ZIP archive", None
    if head.startswith(b"\x1f\x8b"):
        try:
            inner = zlib.decompressobj(31).decompress(blob.lstrip(b"\x00\r\n\t "), MAX_INFLATE)
        except zlib.error:
            inner = b""
        code = _code_in(inner) if inner else None
        return ("gzip-compressed code", code) if code else ("gzip data", None)
    if head.startswith((b"\xff\xd8\xff", PNG_SIG)):
        return "embedded media", None  # HDR gain map / thumbnail: a second image
    code = _code_in(blob)
    if code:
        return "code", code
    if _readable(blob.decode("utf-8", errors="replace")):
        return "text", None
    return "opaque", None


def _rescan(findings: list[Finding], code: str, location: str, where: str) -> None:
    for f in code_scan.scan_source(code, f"{location} ({where})", line_numbers=False):
        f.message = f"[inside image] {f.message}"
        findings.append(f)


# --- per-image checks -------------------------------------------------------------


def _check_trailer(findings: list[Finding], data: bytes, end: int, fmt: str, marker: str, loc: str) -> None:
    trailer = data[end:]
    if len(trailer) < MIN_TRAILER or not trailer.strip(b"\x00\r\n\t "):
        return  # a stray newline, or nothing but padding
    kind, code = _classify(trailer)
    n = len(trailer)
    if code is not None:
        findings.append(Finding(CHECK, "malicious", 50,
                                f"{n} bytes of {kind} hidden after the {fmt} {marker}: `{_preview(code)}`", loc))
        _rescan(findings, code, loc, "after image end")
    elif "executable" in kind:
        findings.append(Finding(CHECK, "malicious", 45, f"{kind} ({n} bytes) appended after the {fmt} {marker}", loc))
    elif kind in ("ZIP archive", "gzip data"):
        findings.append(Finding(CHECK, "suspicious", 30, f"{kind} ({n} bytes) appended after the {fmt} {marker} "
                                                         "(image/archive polyglot)", loc))
    elif kind == "embedded media":
        findings.append(Finding(CHECK, "info", 2, f"Second media stream ({n} bytes) after the {fmt} {marker} "
                                                  "(motion photo / gain map?)", loc))
    elif kind == "text":
        findings.append(Finding(CHECK, "info", 5, f"{n} bytes of text after the {fmt} {marker}: "
                                                  f"`{_preview(trailer.decode('utf-8', 'replace'))}`", loc))
    else:
        ent = _entropy(trailer)
        weight = 25 if n >= 1024 and ent >= 7.5 else 10
        note = " (encrypted or compressed payload?)" if weight == 25 else ""
        findings.append(Finding(CHECK, "suspicious", weight, f"{n} bytes of opaque data ({ent:.1f} bits/byte) "
                                                             f"after the {fmt} {marker}{note}", loc))


def _check_metadata(findings: list[Finding], texts: list[tuple[str, str]], fmt: str, loc: str) -> None:
    for key, text in texts:
        if key.startswith(XMP_KEYS) or len(text.strip()) < 20:
            continue
        if STRICT_CODE.search(text) and _readable(text):
            findings.append(Finding(CHECK, "suspicious", 30,
                                    f"Code in {fmt} metadata ({key}): `{_preview(text)}`", loc))
            _rescan(findings, text, loc, f"{fmt} metadata")


def _check_bmp_entropy(findings: list[Finding], data: bytes, loc: str) -> None:
    offset = int.from_bytes(data[10:14], "little")
    pixels = data[offset:]
    if len(pixels) >= 4096:
        ent = _entropy(pixels)
        if ent >= 7.5:  # real uncompressed artwork is far more repetitive than this
            findings.append(Finding(CHECK, "suspicious", 15, f"Uncompressed BMP whose pixels are noise-like "
                                                             f"({ent:.2f} bits/byte): possible LSB/raw payload", loc))


SVG_SCRIPT = re.compile(rb"<script\b|javascript:|\son(?:load|error|click|mouseover)\s*=", re.I)


def _check_file(path: Path, data: bytes, loc: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()

    if suffix == ".svg":
        if SVG_SCRIPT.search(data):
            findings.append(Finding(CHECK, "suspicious", 20, "SVG image with embedded script / event handler", loc))
        return findings

    fmt = image_format(data)
    if fmt is None:
        if suffix in IMAGE_EXT and len(data) >= 8:
            kind, code = _classify(data)
            if code is not None or "executable" in kind:
                shown = f": `{_preview(code)}`" if code else ""
                findings.append(Finding(CHECK, "malicious", 45, f"`{path.name}` is not an image, it is {kind}{shown}", loc))
                if code:
                    _rescan(findings, code, loc, "disguised as image")
            else:
                findings.append(Finding(CHECK, "suspicious", 15, f"`{path.name}` has an image extension but is "
                                                                 f"not a valid image ({kind})", loc))
        return findings

    if fmt in PARSERS:
        parser, marker = PARSERS[fmt]
        end, texts = parser(data)
        if end is not None:
            _check_trailer(findings, data, end, fmt, marker, loc)
        _check_metadata(findings, texts, fmt, loc)
    elif fmt == "BMP":
        _check_bmp_entropy(findings, data, loc)
    return findings


# --- the loader: code that reads image data and executes ----------------------

JS_IMAGE_LIBS = {"sharp", "jimp", "pngjs", "png-js", "jpeg-js", "canvas", "get-pixels", "image-js", "upng-js",
                 "omggif", "gifwrap", "steggy", "lsb", "stegano"}
PY_IMAGE_LIBS = {"PIL", "cv2", "imageio", "skimage", "stegano", "png", "pypng"}
IMAGE_PATH = re.compile(r"\.(?:png|jpe?g|gif|bmp|webp|ico|tiff?)$", re.I)
END_MARKERS = ("IEND", "\xff\xd9", "\\xff\\xd9")
JS_PIXELS = re.compile(r"\.bitmap\s*\.\s*data\b|getPixelColou?r\s*\(|getImageData\s*\(|\.raw\s*\(\s*\)"
                       r"|\.pixels\b|\.data\s*\[")
PY_PIXELS = {"getdata", "getpixel", "load", "tobytes", "frombuffer"}
PY_NET_MODULES = ("socket", "requests", "httpx", "urllib", "urllib2", "urllib3", "aiohttp", "http")


def _js_loader(text: str) -> tuple[set[str], bool, bool]:
    code, strings = code_scan.js_lex(text)
    starts = {off: v for v, off in strings}
    evidence: set[str] = set()
    for val, off in strings:
        if code_scan.JS_IMPORT_BEFORE.search(code[max(0, off - 30):off]):
            if val.removeprefix("node:") in JS_IMAGE_LIBS:
                evidence.add(f"image library `{val}`")
        elif IMAGE_PATH.search(val) and "${" not in val:
            evidence.add(f"reads `{_preview(val, 40)}`")
        if any(m in val for m in END_MARKERS):
            evidence.add(f"searches for the image end marker `{val.encode('unicode_escape').decode()}`")
    if re.search(r"0x[fF][fF]\s*,\s*0x[dD]9|0xffd9", code, re.I):
        evidence.add("searches for the JPEG end marker FFD9")
    if JS_PIXELS.search(code) and any(e.startswith("image library") for e in evidence):
        evidence.add("reads raw pixel data")

    sink = False
    for m in code_scan.JS_EVAL.finditer(code):
        paren = code.find("(", m.start())
        rest = code[paren + 1:]
        if starts.get(paren + 1 + len(rest) - len(rest.lstrip())) != "return this":
            sink = True
            break
    net = bool(code_scan.JS_NET_CALL.search(code))
    return evidence, sink, net


def _py_loader(text: str) -> tuple[set[str], bool, bool]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set(), False, False
    v = code_scan._PyVisitor()
    v.visit(tree)
    evidence: set[str] = set()
    for mod in v.modules:
        if mod.split(".")[0] in PY_IMAGE_LIBS:
            evidence.add(f"image library `{mod}`")
    for val, _line in v.strings:
        if IMAGE_PATH.search(val):
            evidence.add(f"reads `{_preview(val, 40)}`")
        if any(m in val for m in END_MARKERS):
            evidence.add("searches for the image end marker")
    if any(e.startswith("image library") for e in evidence) and \
            any(q.rsplit(".", 1)[-1] in PY_PIXELS for q, _ in v.calls):
        evidence.add("reads raw pixel data")
    sink = any(q in code_scan.PY_EXEC for q, _ in v.calls)
    net = any(code_scan._is_net(q) for q, _ in v.calls) or \
        any(m.split(".")[0] in PY_NET_MODULES for m in v.modules)
    return evidence, sink, net


def _check_loader(path: Path, text: str, loc: str) -> Finding | None:
    if len(text) >= code_scan.SMALL_FILE:
        return None  # in big bundles, "same file" co-occurrence means nothing
    suffix = path.suffix.lower()
    if suffix in code_scan.JS_EXT:
        evidence, sink, net = _js_loader(text)
    elif suffix in code_scan.PY_EXT:
        evidence, sink, net = _py_loader(text)
    else:
        return None
    # an image path next to eval is just a web page with pictures: require a strong signal
    strong = any(e.startswith("image library") or "end marker" in e for e in evidence)
    if not strong or not sink:
        return None
    weight = 25
    if any("end marker" in e or "pixel" in e for e in evidence):
        weight += 15
    if net:
        weight += 15
        evidence.add("downloads data")
    weight = min(weight, 55)
    return Finding(CHECK, "malicious" if weight >= 40 else "suspicious", weight,
                   "Image-stego loader shape: " + ", ".join(sorted(evidence)) + ", then runs dynamic code", loc)


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    pkg_dir = Path(pkg_dir)
    findings: list[Finding] = []
    for path in iter_files(pkg_dir):
        suffix = path.suffix.lower()
        is_code = suffix in code_scan.JS_EXT or suffix in code_scan.PY_EXT
        if not (is_code or suffix in IMAGE_EXT or suffix == ".svg"):
            # still catch real images hiding under other names (e.g. data.bin)
            try:
                with path.open("rb") as fh:
                    head = fh.read(16)
            except OSError:
                continue
            if image_format(head) is None:
                continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        loc = rel(path, pkg_dir)
        if is_code:
            loader = _check_loader(path, data.decode("utf-8", errors="surrogateescape"), loc)
            if loader:
                findings.append(loader)
        else:
            findings.extend(_check_file(path, data, loc))
    return findings
