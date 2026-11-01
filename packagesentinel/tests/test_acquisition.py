"""Acquisition: safe extraction, metadata, npm + PyPI exact-version fetch (Issue #2).

Archives are built in memory and registries are faked (tests/acquisition_fixtures.py);
nothing touches the network and nothing from an archive is ever executed.
Runs with plain unittest: python -m unittest tests.test_acquisition
"""

import asyncio
import hashlib
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.acquisition import _http  # noqa: E402
from app.acquisition.archive import Limits, cleanup, extract_archive, extract_upload, sha256_bytes  # noqa: E402
from app.acquisition.errors import (  # noqa: E402
    AcquisitionError,
    ArchiveValidationError,
    ExtractionError,
    PackageNotFoundError,
    RegistryError,
    VersionNotFoundError,
)
from app.acquisition.npm import fetch_npm  # noqa: E402
from app.acquisition.pypi import fetch_pypi  # noqa: E402
from app.detection.resolver import resolve  # noqa: E402
from tests.acquisition_fixtures import FakeRegistry, make_tgz, make_zip, npm_routes  # noqa: E402

PACKAGE_JSON = """{
  "name": "demo-lib", "version": "1.2.3",
  "dependencies": {"left-pad": "^1.3.0"},
  "maintainers": [{"name": "alice", "email": "a@example.invalid"}],
  "repository": {"type": "git", "url": "git+https://github.com/example/demo-lib.git"}
}"""
NPM_TGZ = make_tgz({"package/package.json": PACKAGE_JSON, "package/index.js": "module.exports = 1;\n",
                    "package/lib/util.js": "exports.x = 2;\n"})

PKG_INFO = """Metadata-Version: 2.1
Name: demo-py
Version: 0.4.0
Summary: A demo project
Author: Bob Builder
Project-URL: Source, https://github.com/example/demo-py
Requires-Dist: requests (>=2.0)
Requires-Dist: rich; extra == "cli"
"""
SDIST = make_tgz({"demo-py-0.4.0/PKG-INFO": PKG_INFO, "demo-py-0.4.0/setup.py": "from setuptools import setup\nsetup()\n",
                  "demo-py-0.4.0/demo_py/__init__.py": "VALUE = 1\n"})
WHEEL = make_zip({"demo_py/__init__.py": "VALUE = 1\n",
                  "demo_py-0.4.0.dist-info/METADATA": PKG_INFO.replace("Metadata-Version: 2.1", "Metadata-Version: 2.1"),
                  "demo_py-0.4.0.dist-info/RECORD": ""})


class SafeExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.outside = Path(self.tmp.name)
        self.dest = self.outside / "extract"

    def tearDown(self):
        self.tmp.cleanup()

    def assert_nothing_escaped(self):
        names = {p.name for p in self.outside.rglob("*") if not str(p).startswith(str(self.dest))}
        self.assertEqual(names - {"extract"}, set(), "a file was written outside the extraction root")

    def test_valid_npm_tarball(self):
        pkg_dir, meta = extract_upload(NPM_TGZ, dest=self.dest)
        self.assertEqual(pkg_dir.name, "package")
        self.assertTrue((pkg_dir / "lib" / "util.js").is_file())
        self.assertEqual((meta["name"], meta["ecosystem"], meta["version"]), ("demo-lib", "npm", "1.2.3"))
        self.assertEqual(meta["dependencies"], {"left-pad": "^1.3.0"})
        self.assertEqual(meta["maintainers"], ["alice"])
        self.assertEqual(meta["repo_url"], "https://github.com/example/demo-lib")
        self.assertIsNone(meta["published"])
        self.assertIsNone(meta["downloads"])
        acq = meta["acquisition"]
        self.assertEqual(acq["archive_sha256"], hashlib.sha256(NPM_TGZ).hexdigest())
        self.assertEqual((acq["archive_format"], acq["files"], acq["warnings"]), ("tar.gz", 3, []))

    def test_extracted_files_are_never_executable(self):
        pkg_dir, _ = extract_upload(NPM_TGZ, dest=self.dest)  # tar entries were 0755
        mode = stat.S_IMODE(os.stat(pkg_dir / "index.js").st_mode)
        self.assertEqual(mode & 0o111, 0)

    def test_valid_pypi_sdist(self):
        pkg_dir, meta = extract_upload(SDIST, dest=self.dest)
        self.assertEqual(pkg_dir.name, "demo-py-0.4.0")
        self.assertTrue((pkg_dir / "setup.py").is_file())
        self.assertEqual((meta["name"], meta["ecosystem"], meta["version"]), ("demo-py", "pypi", "0.4.0"))
        self.assertEqual(meta["dependencies"], {"requests": "(>=2.0)", "rich": '; extra == "cli"'})
        self.assertEqual(meta["repo_url"], "https://github.com/example/demo-py")
        self.assertEqual(meta["maintainers"], ["Bob Builder"])

    def test_valid_wheel(self):
        pkg_dir, meta = extract_upload(WHEEL, dest=self.dest)
        self.assertEqual(pkg_dir, self.dest)  # no single top-level dir in a wheel
        self.assertEqual((meta["name"], meta["version"], meta["acquisition"]["archive_format"]),
                         ("demo-py", "0.4.0", "zip"))

    def test_zip_symlink_entry_is_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("pkg/a.py", "x = 1\n")
            link = zipfile.ZipInfo("pkg/key")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(link, "/home/user/.ssh/id_rsa")
        pkg_dir, meta = extract_upload(buf.getvalue(), dest=self.dest)
        self.assertFalse((pkg_dir / "key").exists())
        self.assertEqual(meta["acquisition"]["skipped_files"], [{"path": "pkg/key", "reason": "symlink not extracted"}])

    def test_zip_slip_is_rejected(self):
        evil = make_zip({"package/index.js": "ok", "../../evil.py": "import os"})
        with self.assertRaises(ExtractionError) as ctx:
            extract_upload(evil, dest=self.dest)
        self.assertIn("path traversal", str(ctx.exception))
        self.assert_nothing_escaped()
        self.assertEqual(list(self.dest.iterdir()), [])  # rejected before anything was written

    def test_tar_slip_variants_are_rejected(self):
        for name in ("../evil.js", "package/../../evil.js", "/etc/evil.js", "..\\evil.js", "C:/evil.js",
                     "package/./../../evil.js"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ExtractionError):
                    extract_archive(make_tgz({"package/ok.js": "1", name: "x"}), Path(d) / "out")
                self.assertFalse((Path(d) / "evil.js").exists())

    def test_symlinks_are_skipped_and_reported(self):
        tgz = make_tgz({"package/index.js": "1", "package/link/pwned": "x"},
                       links={"package/link": "/etc", "package/key": "/home/user/.ssh/id_rsa"})
        pkg_dir, meta = extract_upload(tgz, dest=self.dest)
        self.assertFalse(any(p.is_symlink() for p in self.dest.rglob("*")))
        skipped = {s["path"] for s in meta["acquisition"]["skipped_files"]}
        self.assertEqual(skipped, {"package/link", "package/key"})
        self.assertTrue(all("not extracted" in w for w in meta["acquisition"]["warnings"]))
        self.assert_nothing_escaped()

    def test_gzip_bomb_is_rejected(self):
        bomb = make_tgz({"package/zeros.bin": b"\0" * (3 * 1024 * 1024)})
        small = Limits(max_total_bytes=1024 * 1024, max_file_bytes=10 * 1024 * 1024)
        with self.assertRaises(ExtractionError) as ctx:
            extract_upload(bomb, dest=self.dest, limits=small)
        self.assertIn("decompression bomb", str(ctx.exception))
        self.assertEqual(list(self.dest.iterdir()), [])  # partial output removed

    def test_zip_bomb_ratio_is_rejected(self):
        bomb = make_zip({"zeros.bin": b"\0" * (8 * 1024 * 1024)})  # ~1000:1
        self.assertLess(len(bomb), 20_000)
        with self.assertRaises(ExtractionError) as ctx:
            extract_upload(bomb, dest=self.dest)
        self.assertIn("zip bomb", str(ctx.exception))

    def test_oversized_file_is_skipped_not_silently_dropped(self):
        tgz = make_tgz({"package/index.js": "1", "package/huge.bin": b"A" * 4096})
        pkg_dir, meta = extract_upload(tgz, dest=self.dest, limits=Limits(max_file_bytes=1024))
        self.assertTrue((pkg_dir / "index.js").exists())
        self.assertFalse((pkg_dir / "huge.bin").exists())
        self.assertEqual(meta["acquisition"]["skipped_files"][0]["path"], "package/huge.bin")
        self.assertIn("too large", meta["acquisition"]["warnings"][0])

    def test_too_many_entries_is_rejected(self):
        tgz = make_tgz({f"package/f{i}.js": "1" for i in range(30)})
        with self.assertRaises(ExtractionError):
            extract_upload(tgz, dest=self.dest, limits=Limits(max_members=10))

    def test_archive_size_limit(self):
        with self.assertRaises(ArchiveValidationError):
            extract_upload(NPM_TGZ, dest=self.dest, limits=Limits(max_archive_bytes=100))

    def test_invalid_archives_fail_safely(self):
        for label, data in (("random bytes", os.urandom(512)), ("truncated tgz", NPM_TGZ[: len(NPM_TGZ) // 2]),
                            ("truncated zip", WHEEL[:40]), ("empty", b""), ("text", b"hello world" * 50),
                            ("empty tgz", make_tgz({}))):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ArchiveValidationError):
                    extract_upload(data, dest=Path(d) / "out")

    def test_gzip_of_nothing_says_empty_not_truncated(self):
        # what `tar czf x.tgz -C dir missing-name` leaves behind: a 20-byte gzip with no tar inside
        import gzip
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ArchiveValidationError) as cm:
            extract_upload(gzip.compress(b""), dest=Path(d) / "out")
        self.assertIn("archive is empty", str(cm.exception))

    def test_sha256_is_reproducible(self):
        self.assertEqual(sha256_bytes(NPM_TGZ), sha256_bytes(bytes(NPM_TGZ)))
        a = extract_upload(NPM_TGZ, dest=self.dest / "a")[1]["acquisition"]["archive_sha256"]
        b = extract_upload(NPM_TGZ, dest=self.dest / "b")[1]["acquisition"]["archive_sha256"]
        self.assertEqual(a, b)
        self.assertNotEqual(a, sha256_bytes(SDIST))

    def test_owned_temp_dir_and_cleanup(self):
        pkg_dir, meta = extract_upload(NPM_TGZ)  # no dest: we own a temp dir
        root = Path(meta["acquisition"]["temp_root"])
        self.assertTrue(root.is_dir() and pkg_dir.is_relative_to(root))
        cleanup(meta)
        self.assertFalse(root.exists())
        cleanup(meta)  # idempotent


class NpmRegistry(unittest.TestCase):
    def setUp(self):
        self.v1 = make_tgz({"package/package.json": PACKAGE_JSON.replace("1.2.3", "1.0.0"), "package/a.js": "1"})
        self.v2 = make_tgz({"package/package.json": PACKAGE_JSON.replace("1.2.3", "1.1.0"), "package/a.js": "2"})
        self.registry = FakeRegistry(npm_routes("demo-lib", {"1.0.0": self.v1, "1.1.0": self.v2}))

    def test_exact_version(self):
        with self.registry.active(), tempfile.TemporaryDirectory() as d:
            pkg_dir, meta = fetch_npm("demo-lib", "1.0.0", dest=d)
            self.assertEqual((pkg_dir / "a.js").read_text(), "1")
        self.assertIn("https://registry.npmjs.org/demo-lib/1.0.0", self.registry.requested)
        self.assertEqual(meta["version"], "1.0.0")
        self.assertEqual(meta["acquisition"]["archive_sha256"], hashlib.sha256(self.v1).hexdigest())
        self.assertEqual(meta["published"], "2026-10-01T00:00:00.000Z")
        self.assertEqual((meta["downloads"], meta["maintainers"]), (1234, ["alice"]))
        self.assertEqual(meta["acquisition"]["source"], "npm-registry")

    def test_latest_when_no_version(self):
        with self.registry.active(), tempfile.TemporaryDirectory() as d:
            _, meta = fetch_npm("demo-lib", dest=d)
        self.assertEqual(meta["version"], "1.1.0")

    def test_integrity_mismatch_is_rejected(self):
        self.registry.routes["https://registry.npmjs.org/demo-lib/-/demo-lib-1.0.0.tgz"] = self.v2  # swapped tarball
        with self.registry.active(), self.assertRaises(ArchiveValidationError):
            fetch_npm("demo-lib", "1.0.0")

    def test_not_found_errors(self):
        with self.registry.active():
            with self.assertRaises(VersionNotFoundError):
                fetch_npm("demo-lib", "9.9.9")
            with self.assertRaises(PackageNotFoundError):
                fetch_npm("no-such-pkg", "1.0.0")

    def test_scoped_name_is_url_encoded(self):
        tgz = make_tgz({"package/package.json": '{"name": "@acme/tool", "version": "2.0.0"}', "package/i.js": "1"})
        routes = npm_routes("@acme%2Ftool", {"2.0.0": tgz})
        with FakeRegistry(routes).active() as reg, tempfile.TemporaryDirectory() as d:
            _, meta = fetch_npm("@acme/tool", "2.0.0", dest=d)
        self.assertIn("https://registry.npmjs.org/@acme%2Ftool/2.0.0", reg.requested)
        self.assertEqual(meta["version"], "2.0.0")

    def test_invalid_names_never_reach_the_network(self):
        for name in ("../../etc/passwd", "a b", "", "x?y=1", "https://evil.invalid"):
            with self.subTest(name=name), self.registry.active() as reg:
                with self.assertRaises(AcquisitionError):
                    fetch_npm(name, "1.0.0")
                self.assertEqual(reg.requested, [])

    def test_resolver_by_name_uses_version_param(self):
        with self.registry.active():
            pkg_dir, meta = resolve("demo-lib", "npm", version="1.1.0")
        try:
            self.assertEqual(meta["version"], "1.1.0")
            self.assertEqual((pkg_dir / "a.js").read_text(), "2")
        finally:
            cleanup(meta)


def pypi_doc(version: str, files: list[dict]) -> dict:
    return {"info": {"name": "demo-py", "version": version, "summary": "A demo project", "author": "Bob Builder",
                     "requires_dist": ["requests (>=2.0)"],
                     "project_urls": {"Source": "https://github.com/example/demo-py"}},
            "urls": files}


def pypi_file(name: str, data: bytes, kind: str) -> dict:
    return {"filename": name, "url": f"https://files.pythonhosted.org/packages/xx/{name}", "packagetype": kind,
            "digests": {"sha256": hashlib.sha256(data).hexdigest()}, "upload_time_iso_8601": "2026-09-30T12:00:00Z"}


class PyPIRegistry(unittest.TestCase):
    def setUp(self):
        wheel_file = pypi_file("demo_py-0.4.0-py3-none-any.whl", WHEEL, "bdist_wheel")
        sdist_file = pypi_file("demo-py-0.4.0.tar.gz", SDIST, "sdist")
        self.routes = {
            "https://pypi.org/pypi/demo-py/json": pypi_doc("0.4.0", [wheel_file, sdist_file]),
            "https://pypi.org/pypi/demo-py/0.4.0/json": pypi_doc("0.4.0", [wheel_file, sdist_file]),
            wheel_file["url"]: WHEEL,
            sdist_file["url"]: SDIST,
        }
        self.registry = FakeRegistry(self.routes)

    def test_exact_version_prefers_sdist(self):
        with self.registry.active(), tempfile.TemporaryDirectory() as d:
            pkg_dir, meta = fetch_pypi("demo-py", "0.4.0", dest=d)
            self.assertTrue((pkg_dir / "setup.py").is_file())  # install-time code is what we want to see
        self.assertIn("https://pypi.org/pypi/demo-py/0.4.0/json", self.registry.requested)
        self.assertEqual((meta["name"], meta["version"], meta["ecosystem"]), ("demo-py", "0.4.0", "pypi"))
        self.assertEqual(meta["acquisition"]["filename"], "demo-py-0.4.0.tar.gz")
        self.assertEqual(meta["acquisition"]["archive_sha256"], hashlib.sha256(SDIST).hexdigest())
        self.assertEqual(meta["published"], "2026-09-30T12:00:00Z")
        self.assertIsNone(meta["downloads"])

    def test_wheel_only_release(self):
        wheel_file = pypi_file("demo_py-0.4.0-py3-none-any.whl", WHEEL, "bdist_wheel")
        self.routes["https://pypi.org/pypi/demo-py/0.4.0/json"] = pypi_doc("0.4.0", [wheel_file])
        with self.registry.active(), tempfile.TemporaryDirectory() as d:
            _, meta = fetch_pypi("demo-py", "0.4.0", dest=d)
        self.assertEqual(meta["acquisition"]["archive_format"], "zip")

    def test_sha256_mismatch_is_rejected(self):
        self.routes["https://files.pythonhosted.org/packages/xx/demo-py-0.4.0.tar.gz"] = SDIST + b"tampered"
        with self.registry.active(), self.assertRaises(ArchiveValidationError):
            fetch_pypi("demo-py", "0.4.0")

    def test_not_found_errors(self):
        with self.registry.active():
            with self.assertRaises(VersionNotFoundError):
                fetch_pypi("demo-py", "9.9.9")
            with self.assertRaises(PackageNotFoundError):
                fetch_pypi("nope-not-here", "1.0")


class HttpGuard(unittest.TestCase):
    def test_non_https_is_refused_before_any_request(self):
        with self.assertRaises(RegistryError):
            _http.fetch("http://registry.npmjs.org/left-pad", 1000)
        with self.assertRaises(RegistryError):
            _http.fetch("file:///etc/passwd", 1000)


class Contract(unittest.TestCase):
    """The async PackageAcquirer contract from Issue #1 (needs pydantic)."""

    def setUp(self):
        try:
            from app.acquisition.contracts import AcquiredPackage, PackageAcquirer  # noqa: F401
            from app.schemas.package import PackageRequest  # noqa: F401
        except ImportError:
            self.skipTest("pydantic not installed")

    def test_npm_acquirer_returns_acquired_package(self):
        from app.acquisition.contracts import AcquiredPackage, PackageAcquirer
        from app.acquisition.npm import NpmAcquirer
        from app.schemas.package import PackageRequest
        tgz = make_tgz({"package/package.json": PACKAGE_JSON, "package/index.js": "1"})
        with FakeRegistry(npm_routes("demo-lib", {"1.2.3": tgz})).active():
            pkg = asyncio.run(NpmAcquirer().acquire(PackageRequest(ecosystem="npm", name="demo-lib", version="1.2.3")))
        self.assertIsInstance(NpmAcquirer(), PackageAcquirer)
        self.assertIsInstance(pkg, AcquiredPackage)
        self.assertEqual((pkg.package_name, pkg.version, pkg.ecosystem), ("demo-lib", "1.2.3", "npm"))
        self.assertEqual(pkg.archive_sha256, hashlib.sha256(tgz).hexdigest())
        self.assertTrue((pkg.extracted_dir / "index.js").is_file())
        root = Path(pkg.temporary_directory.name)
        pkg.cleanup()
        self.assertFalse(root.exists())

    def test_pypi_acquirer_failure_raises_contract_error(self):
        from app.acquisition.contracts import AcquisitionError as ContractError
        from app.acquisition.pypi import PyPIAcquirer
        from app.schemas.package import PackageRequest
        with FakeRegistry({}).active():
            with self.assertRaises(ContractError):  # same class as errors.AcquisitionError
                asyncio.run(PyPIAcquirer().acquire(PackageRequest(ecosystem="pypi", name="nope", version="1.0")))


class ZeroDependency(unittest.TestCase):
    def test_scanner_path_does_not_import_pydantic(self):
        code = ("import sys; import app.detection.resolver, app.acquisition.archive, app.acquisition.npm, "
                "app.acquisition.pypi; assert 'pydantic' not in sys.modules, 'pydantic imported'")
        root = Path(__file__).resolve().parent.parent
        result = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class LocalResolve(unittest.TestCase):
    def test_local_archive_and_folder(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "demo-lib-1.2.3.tgz"
            path.write_bytes(NPM_TGZ)
            pkg_dir, meta = resolve(str(path))
            self.assertEqual((meta["name"], meta["acquisition"]["source"]), ("demo-lib", "local-archive"))
            folder_dir, folder_meta = resolve(str(pkg_dir))
            self.assertEqual((folder_meta["name"], folder_meta["version"]), ("demo-lib", "1.2.3"))
            cleanup(meta)
            self.assertFalse(pkg_dir.exists())


if __name__ == "__main__":
    unittest.main()
