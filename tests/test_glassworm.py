import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from harmonica import glassworm, scanner  # noqa: E402
from harmonica.scanner import Finding, run_scanner  # noqa: E402
from make_samples import tag_encode, vs_encode, zw_encode  # noqa: E402

PAYLOAD = 'require("child_process").exec("id")'


def scan(text: str, path: str = "x.js", is_code: bool = True):
    return glassworm.scan_text(text, path, is_code)


def findings_for(files: dict[str, str]) -> list[Finding]:
    with tempfile.TemporaryDirectory() as d:
        for name, content in files.items():
            p = Path(d, name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return glassworm.check(Path(d), {})


class Decoding(unittest.TestCase):
    def test_variation_selector_payload(self):
        [hit] = scan(f'const a = "{vs_encode(PAYLOAD)}";')
        self.assertEqual(hit.decoded, PAYLOAD)
        self.assertTrue(hit.in_empty_string)
        self.assertEqual((hit.line, hit.col), (1, 12))

    def test_tag_payload(self):
        [hit] = scan(f"# note{tag_encode(PAYLOAD)}\n", "x.py")
        self.assertEqual(hit.decoded, PAYLOAD)

    def test_zero_width_binary_payload(self):
        [hit] = scan(f"x = 1 // {zw_encode(PAYLOAD)}")
        self.assertEqual(hit.decoded, PAYLOAD)

    def test_private_use_bytes_payload(self):
        hidden = "".join(chr(0xE000 + b) for b in PAYLOAD.encode())
        [hit] = scan(f"let q = '{hidden}'")
        self.assertEqual(hit.decoded, PAYLOAD)

    def test_binary_vs_run_is_opaque_not_readable(self):
        hidden = "".join(chr(0xE0100 + b) for b in range(100, 140))
        [hit] = scan(f'k = "{hidden}"')
        self.assertIsNone(hit.decoded)
        self.assertEqual(hit.decoded_bytes, 40)


class FilterPrecision(unittest.TestCase):
    """The emoji / flag / CJK ignore rules must not swallow a real payload."""

    def test_payload_attached_to_an_emoji_is_still_caught(self):
        for base in ["\U0001F600", "\u2764", "\u845b", "a"]:
            with self.subTest(base=base):
                [hit] = scan(f'const s = "{base}{vs_encode(PAYLOAD)}";')
                self.assertEqual(hit.decoded, PAYLOAD)

    def test_payload_after_a_real_emoji_presentation_selector(self):
        # ❤ + VS16 is legit; a payload glued on right after it must still decode
        [hit] = scan(f'x = "\u2764\ufe0f{vs_encode(PAYLOAD)}"')
        self.assertIn(PAYLOAD, hit.decoded)

    def test_payload_after_a_flag_and_zwj_sequence(self):
        flag = "\U0001F3F4" + tag_encode("gbeng") + "\U000E007F"
        hits = scan(f'x = "{flag}\U0001F468\u200d\U0001F469{vs_encode(PAYLOAD)}"')
        self.assertEqual([h.decoded for h in hits], [PAYLOAD])

    def test_boundary_is_three_selectors(self):
        # one VS (+ optional ZWJ) after a visible char is emoji grammar; 2 VS in a row never is
        self.assertEqual(scan('"\u2764\ufe0f"'), [])
        self.assertEqual(len(scan('"\u2764\ufe0f\ufe01"')), 1)


class TrojanSource(unittest.TestCase):
    def test_bidi_in_code_is_its_own_named_check(self):
        [f] = findings_for({"a.js": 'if (role != "user\u202e \u2066// admin\u2069\u2066") {}'})[:1]
        self.assertEqual((f.check, f.severity, f.weight), ("trojan_source_bidi", "malicious", 100))
        self.assertIn("CVE-2021-42574", f.message)


class LegitimateUnicode(unittest.TestCase):
    def test_benign_strings_produce_no_hits(self):
        for s in [
            "﻿const a = 1;",                                   # BOM
            '"❤️"',                                       # emoji + VS16
            '"\U0001F468‍\U0001F469‍\U0001F467"',         # ZWJ family
            '"\U0001F3F3️‍\U0001F308"',                   # VS16 + ZWJ
            '"1️⃣"',                                      # keycap
            '"\U0001F3F4' + tag_encode("gbeng") + '\U000E007F"',    # England flag
            '"葛\U000E0100"',                                   # CJK variant
            '"क्‍ष"',                           # Devanagari ZWJ
            '"می‌خ"',                           # Persian ZWNJ
            'content: "";',                                   # icon font
        ]:
            with self.subTest(s=s):
                self.assertEqual(scan(s), [])

    def test_bidi_in_prose_is_fine_but_not_in_code(self):
        s = "a ⁧مر⁩ b"
        self.assertEqual(scan(s, "README.md", is_code=False), [])
        self.assertEqual(len(scan(s)), 2)

    def test_globalthis_polyfill_is_not_a_decoder_sink(self):
        fs = findings_for({"a.js": 'const VS=0xFE00; const g = Function("return this")();'})
        self.assertEqual(fs, [])


class Findings(unittest.TestCase):
    def test_hidden_code_in_code_file_is_malicious(self):
        f, *rescanned = findings_for({"a.js": f'x("{vs_encode(PAYLOAD)}")'})
        self.assertEqual(f.severity, "malicious")
        self.assertEqual(f.location, "a.js:1:4")
        self.assertIn("child_process", f.message)
        # the decoded payload goes through code_scan too
        self.assertEqual(rescanned[0].location, "a.js:1:4 (decoded payload)")
        self.assertTrue(rescanned[0].message.startswith("[inside hidden payload]"))

    def test_hidden_code_in_docs_is_only_suspicious(self):
        [f] = findings_for({"README.md": f"hi {tag_encode(PAYLOAD)}"})
        self.assertEqual(f.severity, "suspicious")

    def test_decoder_next_to_eval(self):
        src = "const d = s => [...s].map(c => c.codePointAt(0) - 0xE0100 + 16);\neval(d(x));\n"
        [f] = findings_for({"loader.js": src})
        self.assertEqual((f.severity, f.location), ("suspicious", "loader.js:2"))

    def test_invisible_identifier_tricks(self):
        fs = findings_for({
            "filler.js": "function f(a, ㅤ) { run(ㅤ) }",
            "zw.js": "const ad​min = true;",
        })
        self.assertEqual(sorted(f.location for f in fs), ["filler.js:1:15", "filler.js:1:24", "zw.js:1:9"])
        self.assertTrue(all(f.severity == "suspicious" for f in fs))

    def test_invisible_chars_inside_string_data_are_not_identifier_tricks(self):
        fs = findings_for({"table.js": 'const t = "ab\u200bcd";', "data.json": '{"k": "x\u200by"}',
                           "norm.js": 'test("\u1100\u1160\u11a8");'})
        self.assertTrue(all(f.severity == "info" for f in fs))

    def test_stray_zero_width_is_low_noise_info(self):
        [f] = findings_for({"a.js": 'log("hello​ world")'})
        self.assertEqual((f.severity, f.weight), ("info", 2))

    def test_messages_never_contain_raw_invisible_chars(self):
        fs = findings_for({"a.js": f'x("{vs_encode(PAYLOAD + chr(0x200B))}")'})
        self.assertFalse(glassworm.HIDDEN_RUN.search(fs[0].message))


class Spine(unittest.TestCase):
    def test_crashing_check_becomes_info_finding(self):
        def boom(pkg_dir, meta):
            raise RuntimeError("kaboom")

        original = scanner._check_groups
        scanner._check_groups = lambda: [("raw", [("boom", boom)])]
        try:
            with tempfile.TemporaryDirectory() as d:
                [f] = run_scanner(d, {})
        finally:
            scanner._check_groups = original
        self.assertEqual((f.check, f.severity, f.weight), ("boom", "info", 0))
        self.assertIn("kaboom", f.message)

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as pkg:
            Path(outside, "secret.js").write_text(f'"{vs_encode(PAYLOAD)}"', encoding="utf-8")
            os.symlink(Path(outside, "secret.js"), Path(pkg, "link.js"))
            os.symlink(outside, Path(pkg, "linkdir"))
            self.assertEqual(list(scanner.iter_files(pkg)), [])

    def test_bad_severity_rejected(self):
        with self.assertRaises(ValueError):
            Finding("x", "critical", 1, "m")


class Fixtures(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent / "test-samples"

    def test_glassworm_demo_is_malicious(self):
        fs = run_scanner(self.ROOT / "malicious" / "glassworm-demo", {})
        self.assertGreaterEqual(sum(f.severity == "malicious" for f in fs), 2)

    def test_emoji_utils_is_clean(self):
        self.assertEqual(run_scanner(self.ROOT / "benign" / "emoji-utils", {}), [])


if __name__ == "__main__":
    unittest.main()
