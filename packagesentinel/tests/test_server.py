"""server.py: the thin demo doorway. Skipped unless fastapi + httpx are installed
(the detection package itself never needs them). No live network."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    import server
except ImportError:  # zero-dep environment: nothing to test here
    server = None

from tests.acquisition_fixtures import FakeRegistry, make_tgz, make_zip, npm_routes, tgz_from_dir

SAMPLES = Path(__file__).parent / "fixtures" / "detection-samples"


def temp_dirs() -> set[str]:
    return {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("pkgsentinel-")}


@unittest.skipIf(server is None, "fastapi / httpx not installed")
class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(server.app, raise_server_exceptions=False)

    def setUp(self):
        self.before = temp_dirs()

    def tearDown(self):
        self.assertEqual(temp_dirs() - self.before, set(), "temp dirs left behind")

    def upload(self, path, data, **fields):
        return self.client.post(path, files={"file": ("pkg.tgz", data, "application/gzip")}, data=fields)

    # --- /scan ----------------------------------------------------------------

    def test_scan_clean_sample(self):
        r = self.upload("/scan", tgz_from_dir(SAMPLES / "benign" / "clean-math"))
        self.assertEqual(r.status_code, 200, r.text)
        v = r.json()
        self.assertEqual((v["package"], v["band"]), ("clean-math", "safe"))

    def test_scan_malicious_sample_matches_build_verdict_shape(self):
        from app.detection.resolver import cleanup, extract_upload
        from app.detection.scanner import run_scanner
        from app.detection.scoring import build_verdict

        data = tgz_from_dir(SAMPLES / "malicious" / "fake-stealer")
        r = self.upload("/scan", data)
        self.assertEqual(r.status_code, 200, r.text)
        pkg_dir, meta = extract_upload(data)
        try:
            expected = build_verdict(meta, run_scanner(pkg_dir, meta))
        finally:
            cleanup(meta)
        self.assertEqual(r.json(), json.loads(json.dumps(expected)))
        self.assertEqual(r.json()["band"], "malicious")

    def test_scan_zip_slip_is_a_clean_400(self):
        r = self.upload("/scan", make_zip({"../../evil.py": "x = 1\n"}))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["kind"], "ExtractionError")
        self.assertIn("path traversal", r.json()["error"])

    def test_scan_garbage_is_a_clean_400(self):
        r = self.upload("/scan", b"definitely not an archive")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["kind"], "ArchiveValidationError")

    def test_scan_requires_an_upload(self):
        self.assertEqual(self.client.post("/scan", json={"pkg": "x"}).status_code, 400)
        r = self.client.post("/scan", data={"ecosystem": "npm"})
        self.assertEqual(r.status_code, 400)

    def test_scan_rejects_unknown_ecosystem(self):
        r = self.upload("/scan", make_tgz({"package/index.js": "1"}), ecosystem="maven")
        self.assertEqual(r.status_code, 400)

    def test_oversized_upload_is_413(self):
        with mock.patch.object(server, "MAX_BODY", 1000):
            r = self.upload("/scan", b"x" * 5000)
        self.assertEqual(r.status_code, 413)

    def test_unexpected_error_has_no_stack_trace(self):
        with mock.patch.object(server, "run_scanner", side_effect=RuntimeError("boom /secret/path")):
            r = self.upload("/scan", make_tgz({"package/index.js": "1"}))
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json(), {"error": "scan failed: RuntimeError", "kind": "InternalError"})

    def test_cors_allows_any_origin(self):
        r = self.client.options("/scan", headers={"Origin": "http://localhost:5173",
                                                  "Access-Control-Request-Method": "POST"})
        self.assertEqual(r.headers.get("access-control-allow-origin"), "*")

    # --- /scan-name -----------------------------------------------------------

    def test_scan_name_through_mocked_registry(self):
        tgz = make_tgz({"package/package.json": json.dumps({"name": "tiny", "version": "1.0.0"}),
                        "package/index.js": "module.exports = 1;\n"})
        with FakeRegistry(npm_routes("tiny", {"1.0.0": tgz})).active():
            r = self.client.post("/scan-name", json={"pkg": "tiny", "ecosystem": "npm", "version": "1.0.0"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["package"], r.json()["version"]), ("tiny", "1.0.0"))

    def test_scan_name_never_reads_local_paths(self):
        for pkg in (str(SAMPLES / "malicious" / "fake-stealer"), "/etc", "../.."):
            with self.subTest(pkg=pkg), FakeRegistry({}).active() as reg:
                r = self.client.post("/scan-name", json={"pkg": pkg})
                self.assertEqual(r.status_code, 400, r.text)
                self.assertEqual(reg.requested, [])

    def test_scan_name_not_found_is_404(self):
        with FakeRegistry({}).active():
            r = self.client.post("/scan-name", json={"pkg": "nope-not-here", "version": "1.0.0"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["kind"], "PackageNotFoundError")

    def test_scan_name_validates_input(self):
        self.assertEqual(self.client.post("/scan-name", json={}).status_code, 400)
        self.assertEqual(self.client.post("/scan-name", content=b"{nope").status_code, 400)

    # --- /diff ----------------------------------------------------------------

    def test_diff_two_uploads(self):
        old = tgz_from_dir(SAMPLES / "diff" / "update-demo-1.0.0")
        new = tgz_from_dir(SAMPLES / "diff" / "update-demo-1.0.1")
        r = self.client.post("/diff", files={"old": ("old.tgz", old), "new": ("new.tgz", new)})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["headline"].startswith("clean at 1.0.0 → malicious at 1.0.1"))
        self.assertTrue(r.json()["added_findings"])

    def test_diff_by_name_through_mocked_registry(self):
        old = tgz_from_dir(SAMPLES / "diff" / "update-demo-1.0.0")
        new = tgz_from_dir(SAMPLES / "diff" / "update-demo-1.0.1")
        with FakeRegistry(npm_routes("update-demo", {"1.0.0": old, "1.0.1": new})).active():
            r = self.client.post("/diff", json={"pkg": "update-demo", "old": "1.0.0", "new": "1.0.1"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("malicious at 1.0.1", r.json()["headline"])

    def test_diff_bad_inputs(self):
        self.assertEqual(self.client.post("/diff", json={"pkg": "x", "old": "1.0.0"}).status_code, 400)
        r = self.client.post("/diff", files={"old": ("o.tgz", make_tgz({"package/a.js": "1"}))})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/diff", files={"old": ("o.tgz", make_tgz({"package/a.js": "1"})),
                                             "new": ("n.zip", make_zip({"../x.js": "1"}))})
        self.assertEqual((r.status_code, r.json()["kind"]), (400, "ExtractionError"))


@unittest.skipIf(server is None, "fastapi / httpx not installed")
class MultipartParser(unittest.TestCase):
    def test_binary_content_is_byte_exact(self):
        payload = bytes(range(256)) * 4 + b"\r\n--not-the-boundary\r\n\r\n"
        body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.tgz\"\r\n"
                b"Content-Type: application/gzip\r\n\r\n" + payload + b"\r\n"
                b"--XyZ\r\nContent-Disposition: form-data; name=\"ecosystem\"\r\n\r\nnpm\r\n--XyZ--\r\n")
        fields = server.parse_multipart(body, "multipart/form-data; boundary=XyZ")
        self.assertEqual(fields["file"], ("a.tgz", payload))
        self.assertEqual(fields["ecosystem"], (None, b"npm"))


if __name__ == "__main__":
    unittest.main()
