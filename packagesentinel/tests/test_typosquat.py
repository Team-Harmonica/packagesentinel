import tempfile
import unittest
from pathlib import Path

from app.detection.analyzers import PackageContentAnalyzer, PackageIdentityAnalyzer
from app.detection.scanner import run_scanner
from app.detection.typosquat import check


class TyposquatDetectorTests(unittest.IsolatedAsyncioTestCase):
    def test_detects_single_edit_in_pypi_package_name(self):
        with tempfile.TemporaryDirectory() as directory:
            [finding] = check(
                Path(directory),
                {"ecosystem": "pypi", "name": "reqeusts"},
            )

        self.assertEqual(finding.check, "typosquat")
        self.assertEqual(finding.severity, "suspicious")
        self.assertEqual(finding.weight, 25)
        self.assertIn("`reqeusts`", finding.message)
        self.assertIn("`requests`", finding.message)

    def test_detects_adjacent_transposition(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = check(
                Path(directory),
                {"ecosystem": "npm", "package_name": "exrpess"},
            )
        self.assertEqual(len(findings), 1)
        self.assertIn("`express`", findings[0].message)

    def test_detects_confusable_character_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = check(
                Path(directory),
                {"ecosystem": "pypi", "name": "r\u0435quests"},
            )
        self.assertEqual(len(findings), 1)
        self.assertIn("confusable", findings[0].message)
        self.assertIn("`requests`", findings[0].message)

    def test_pypi_normalizes_separator_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = check(
                Path(directory),
                {"ecosystem": "pypi", "name": "re..quests"},
            )
        self.assertEqual(len(findings), 1)

    def test_exact_known_names_are_not_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            for ecosystem, name in (("npm", "react"), ("pypi", "requests")):
                with self.subTest(ecosystem=ecosystem):
                    self.assertEqual(
                        check(Path(directory), {"ecosystem": ecosystem, "name": name}),
                        [],
                    )

    def test_requires_supported_ecosystem_and_package_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            for metadata in (
                {"ecosystem": "maven", "name": "reqeusts"},
                {"ecosystem": "pypi"},
                {"ecosystem": "pypi", "name": "   "},
                {"name": "reqeusts"},
            ):
                with self.subTest(metadata=metadata):
                    self.assertEqual(check(Path(directory), metadata), [])

    def test_ignores_distant_and_ambiguous_names(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                check(Path(directory), {"ecosystem": "pypi", "name": "requestsxx"}),
                [],
            )

    def test_scanner_registers_and_adapter_normalizes_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = {"ecosystem": "pypi", "name": "reqeusts"}
            detector_findings = run_scanner(directory, metadata)
            findings = PackageContentAnalyzer.analyze_directory(directory, metadata)

        self.assertEqual(
            [item.check for item in detector_findings if item.check == "typosquat"],
            ["typosquat"],
        )
        finding = next(item for item in findings if item.category == "typosquatting")
        self.assertEqual(finding.source, "packagesentinel_static")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.metadata["detector"], "typosquat")

    async def test_package_identity_analyzer_runs_without_package_contents(self):
        from app.schemas.package import Ecosystem, PackageRequest

        request = PackageRequest(
            ecosystem=Ecosystem.PYPI,
            name="reqeusts",
            version="1.0.0",
        )
        result = await PackageIdentityAnalyzer().analyze(request)

        self.assertEqual(result.status.value, "completed")
        self.assertEqual(result.stage_key, "metadata_analysis")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, "metadata_analysis")


if __name__ == "__main__":
    unittest.main()
