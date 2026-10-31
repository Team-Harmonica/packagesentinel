import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection import diff  # noqa: E402
from app.detection.scanner import Finding  # noqa: E402

SAMPLES = Path(__file__).resolve().parent / "fixtures" / "detection-samples" / "diff"
OLD, NEW = SAMPLES / "update-demo-1.0.0", SAMPLES / "update-demo-1.0.1"

EVAL_SRC = "const cp = require('child_process');\ncp.exec(userInput);\n"


def make_pkg(root: Path, version: str, files: dict[str, str], deps: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": "p", "version": version, "dependencies": deps or {}}))
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content)
    return root


def run_cli(*args) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = diff.main([str(a) for a in args])
    return code, out.getvalue()


class Fingerprints(unittest.TestCase):
    def test_normalize_drops_counts_numbers_and_blobs(self):
        a = diff.normalize("Spawns a process via child_process (`exec`) (x3)")
        b = diff.normalize("Spawns a process via child_process (`exec`) (x7)")
        self.assertEqual(a, b)
        self.assertEqual(diff.normalize("Hidden payload: 161 invisible"), diff.normalize("Hidden payload: 163 invisible"))
        self.assertIn("<blob>", diff.normalize("decodes: `Y29uc29sZS5sb2coImhpIik7Y29uc29sZQ==`"))
        self.assertIn("<hex>", diff.normalize("hash deadbeefdeadbeefdeadbeef"))

    def test_location_keeps_file_drops_line_and_col(self):
        self.assertEqual(diff.location_file("scripts/setup.js:14:3 (decoded payload)"), "scripts/setup.js")
        self.assertEqual(diff.location_file("a.py:2"), "a.py")
        self.assertEqual(diff.location_file("dropper/__init__.py"), "dropper/__init__.py")

    def test_same_finding_in_another_file_is_a_different_fingerprint(self):
        f1 = Finding("dangerous_call", "suspicious", 10, "Dynamic code execution: `eval(`", "lib.js:3")
        f2 = Finding("dangerous_call", "suspicious", 10, "Dynamic code execution: `eval(`", "postinstall.js:3")
        self.assertNotEqual(diff.fingerprint(f1), diff.fingerprint(f2))

    def test_stable_under_line_shifts(self):
        with tempfile.TemporaryDirectory() as d:
            old = make_pkg(Path(d, "old"), "1.0.0", {"index.js": EVAL_SRC})
            new = make_pkg(Path(d, "new"), "1.0.1", {"index.js": "// banner\n// more banner\n\n" + EVAL_SRC})
            r = diff.diff_dirs(old, new)
        self.assertEqual(r["added_findings"], [])
        self.assertEqual(r["removed_findings"], [])
        self.assertGreater(r["unchanged_count"], 0)
        self.assertEqual(r["files"]["modified"], ["index.js", "package.json"])


class Changes(unittest.TestCase):
    def test_added_vs_removed_findings(self):
        with tempfile.TemporaryDirectory() as d:
            old = make_pkg(Path(d, "old"), "1.0.0", {"a.js": EVAL_SRC})
            new = make_pkg(Path(d, "new"), "1.0.1",
                           {"b.js": 'const u = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz";'})
            r = diff.diff_dirs(old, new)
        self.assertEqual({f["check"] for f in r["added_findings"] if f["check"] != "capability"}, {"network_exfil"})
        self.assertIn("dangerous_call", {f["check"] for f in r["removed_findings"]})
        self.assertEqual(r["files"], {"added": ["b.js"], "deleted": ["a.js"], "modified": ["package.json"]})

    def test_multiset_semantics(self):
        f = Finding("dangerous_call", "suspicious", 10, "Dynamic code execution: `eval(`", "a.js:1")
        added, removed, unchanged = diff.diff_findings([f], [f, f])
        self.assertEqual((len(added), len(removed), len(unchanged)), (1, 0, 1))

    def test_dependency_diff(self):
        r = diff.diff_dependencies({"dependencies": {"a": "1.0.0", "b": "^2.0.0", "gone": "1"}},
                                   {"dependencies": {"a": "1.0.0", "b": "^2.1.0", "flatmap-stream": "0.1.1"}})
        self.assertEqual(r, {"added": {"flatmap-stream": "0.1.1"}, "removed": {"gone": "1"},
                             "changed": {"b": {"from": "^2.0.0", "to": "^2.1.0"}}})
        # PyPI-style list of names works too
        self.assertEqual(diff.diff_dependencies({"dependencies": ["x"]}, {"dependencies": ["x", "y"]})["added"], {"y": ""})

    def test_version_bump(self):
        self.assertEqual(diff.version_bump("1.0.0", "1.0.1"), "patch")
        self.assertEqual(diff.version_bump("1.0.9", "1.2.0"), "minor")
        self.assertEqual(diff.version_bump("1.4.2", "2.0.0"), "major")
        self.assertIsNone(diff.version_bump("1.0.1", "1.0.0"))
        self.assertIsNone(diff.version_bump("latest", "next"))


class DemoPair(unittest.TestCase):
    def test_headline_clean_to_malicious(self):
        r = diff.diff_dirs(OLD, NEW)
        h = r["headline"]
        self.assertTrue(h.startswith("clean at 1.0.0 → malicious at 1.0.1: added "), h)
        for part in ("webhook_exfil", "ssh_aws_read", "in scripts/setup.js", "new postinstall script",
                     "new dependency flatmap-stream", "score 0 → 100"):
            self.assertIn(part, h)

    def test_update_risk_combo_and_json_shape(self):
        r = diff.diff_dirs(OLD, NEW)
        self.assertEqual(r["bump"], "patch")
        self.assertTrue(any("patch release (hijacked-update shape)" in line for line in r["explanation"]))
        for key in ("package", "old", "new", "added_findings", "removed_findings", "dependencies", "files", "headline"):
            self.assertIn(key, r)
        self.assertEqual(r["files"]["added"], ["scripts/setup.js"])
        json.dumps(r)  # must be serializable for --json

    def test_no_update_bonus_on_major_bump(self):
        with tempfile.TemporaryDirectory() as d:
            src = 'const k = require("fs").readFileSync(home + "/.ssh/id_rsa");'
            old = make_pkg(Path(d, "old"), "1.0.0", {"a.js": "x = 1;"})
            new = make_pkg(Path(d, "new"), "2.0.0", {"a.js": src})
            r = diff.diff_dirs(old, new)
        self.assertEqual(r["bump"], "major")
        self.assertFalse(any("hijacked-update" in line for line in r["explanation"]))

    def test_identical_versions_give_an_empty_diff(self):
        r = diff.diff_dirs(NEW, NEW)
        self.assertEqual((r["added_findings"], r["removed_findings"]), ([], []))
        self.assertEqual(r["files"], {"added": [], "deleted": [], "modified": []})
        self.assertFalse(any(r["dependencies"].values()) or any(r["install_scripts"].values()))
        self.assertIn("no new risk signals", r["headline"])
        self.assertFalse(r["worse"])


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(run_cli(OLD, NEW)[0], 1)   # new version malicious
        self.assertEqual(run_cli(OLD, OLD)[0], 0)   # nothing changed, clean
        code, out = run_cli(NEW, OLD)               # going back to the clean version
        self.assertEqual(code, 0)
        self.assertIn("malicious at 1.0.1 → clean at 1.0.0", out)

    def test_json_flag(self):
        code, out = run_cli(OLD, NEW, "--json")
        self.assertEqual(json.loads(out)["new"]["band"], "malicious")

    def test_by_name_diff_through_mocked_npm_registry(self):
        # resolve(pkg, ecosystem, version) fetches each exact version; registry is faked, no network
        from tests.acquisition_fixtures import FakeRegistry, npm_routes, tgz_from_dir
        registry = FakeRegistry(npm_routes("update-demo", {"1.0.0": tgz_from_dir(OLD), "1.0.1": tgz_from_dir(NEW)}))
        with registry.active():
            code, out = run_cli("update-demo", "1.0.0", "1.0.1")
        self.assertEqual(code, 1)
        self.assertIn("clean at 1.0.0 → malicious at 1.0.1", out)
        self.assertIn("new dependency flatmap-stream", out)

    def test_by_name_unknown_version_exits_2(self):
        from tests.acquisition_fixtures import FakeRegistry, npm_routes, tgz_from_dir
        registry = FakeRegistry(npm_routes("update-demo", {"1.0.0": tgz_from_dir(OLD)}))
        with registry.active():
            self.assertEqual(run_cli("update-demo", "1.0.0", "9.9.9")[0], 2)


if __name__ == "__main__":
    unittest.main()
