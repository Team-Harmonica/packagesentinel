"""Issue #6: metadata.py + typosquat.py (popularity guard). Offline only."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.detection import metadata, typosquat
from app.detection.scanner import Finding, run_scanner
from app.detection.scoring import build_verdict, finding_type

NOW = datetime.now(timezone.utc)
DAYS_AGO = lambda n: (NOW - timedelta(days=n)).isoformat()  # noqa: E731

LEGIT = {
    "name": "lodash", "ecosystem": "npm", "version": "4.17.21",
    "published": DAYS_AGO(400), "created": DAYS_AGO(4000), "downloads": 50_000_000,
    "maintainers": ["jdalton", "mathias"], "previous_maintainers": ["jdalton"],
    "previous_version": "4.17.20", "repo_url": "https://github.com/lodash/lodash",
    "dependencies": {},
}
SHADY = {"name": "left-padder", "ecosystem": "npm", "version": "1.0.0",
         "created": DAYS_AGO(2), "downloads": 7, "repo_url": None, "maintainers": ["x"]}


def meta_check(**overrides):
    return metadata.check(Path(), {**LEGIT, **overrides})


def typo(name, ecosystem="npm", **meta):
    return typosquat.check(Path(), {"name": name, "ecosystem": ecosystem, **meta})


class MetadataRules(unittest.TestCase):
    def test_legit_metadata_is_clean(self):
        self.assertEqual(metadata.check(Path(), LEGIT), [])

    def test_new_low_downloads_no_repo_is_flagged(self):
        findings = metadata.check(Path(), SHADY)
        self.assertEqual([f.rule_id for f in findings], ["META001", "META002", "META004"])
        self.assertTrue(all(f.check == "metadata" and f.category and f.confidence for f in findings))
        self.assertEqual({finding_type(f) for f in findings}, {"new_package", "low_downloads", "no_repo"})

    def test_no_identity_or_no_data_means_no_findings(self):
        self.assertEqual(metadata.check(Path(), {}), [])
        self.assertEqual(metadata.check(Path(), {"ecosystem": "npm"}), [])
        bare = {"name": "x", "repo_url": "https://github.com/a/x"}  # local folder: no registry data
        self.assertEqual(metadata.check(Path(), bare), [])
        # an upload whose package.json omits "repository" is not penalised without registry data
        self.assertEqual(metadata.check(Path(), {"name": "x", "repo_url": None}), [])

    def test_release_date_fallback_is_worded_honestly(self):
        [f] = metadata.check(Path(), {"name": "p", "published": DAYS_AGO(1), "repo_url": "https://github.com/a/p"})
        self.assertEqual(f.rule_id, "META001")
        self.assertTrue(f.message.startswith("This release was published"))
        self.assertEqual(finding_type(f), "new_package")

    def test_maintainer_takeover(self):
        [f] = meta_check(maintainers=["eve"], previous_maintainers=["jdalton", "mathias"])
        self.assertEqual((f.rule_id, f.severity), ("META003", "suspicious"))
        self.assertIn("4.17.20", f.message)
        self.assertEqual(finding_type(f), "maintainer_change")

    def test_added_maintainer_is_not_a_takeover(self):
        self.assertEqual(meta_check(maintainers=["jdalton", "eve"]), [])
        self.assertEqual(meta_check(previous_maintainers=[]), [])  # no history -> no guess

    def test_star_jacking_repo(self):
        [f] = metadata.check(Path(), {**LEGIT, "name": "reqeusts", "ecosystem": "pypi",
                                      "repo_url": "https://github.com/psf/requests"})
        self.assertEqual((f.rule_id, f.severity), ("META004", "suspicious"))
        self.assertIn("`requests`", f.message)
        self.assertEqual(finding_type(f), "repo_mismatch")

    def test_monorepos_and_forks_are_not_mismatches(self):
        for name, repo in (("@babel/core", "https://github.com/babel/babel"),
                           ("react-dom", "https://github.com/facebook/react"),
                           ("my-tool", "https://github.com/me/something-else"),
                           ("my-tool", "https://example.com/self-hosted")):
            with self.subTest(name=name, repo=repo):
                self.assertEqual(meta_check(name=name, repo_url=repo), [])

    def test_version_jump(self):
        [f] = meta_check(version="9.0.0", previous_version="1.2.0")
        self.assertEqual(f.rule_id, "META005")
        self.assertEqual(finding_type(f), "version_jump")
        [f] = meta_check(version="99.0.0", previous_version=None)
        self.assertIn("dependency-confusion", f.message)

    def test_normal_versions_are_fine(self):
        for version, prev in (("2.0.0", "1.9.3"), ("131.0.1", "130.0.0"), ("5.0.0", None)):
            with self.subTest(version=version):
                self.assertEqual(meta_check(version=version, previous_version=prev), [])

    def test_every_rule_scores_as_one_type(self):
        findings = (metadata.check(Path(), SHADY)
                    + meta_check(maintainers=["eve"])
                    + meta_check(version="99.0.0", previous_version="1.0.0"))
        self.assertEqual(sorted({f.rule_id for f in findings}),
                         ["META001", "META002", "META003", "META004", "META005"])
        self.assertNotIn("metadata", {finding_type(f) for f in findings})  # never the unknown fallback


class TyposquatGuard(unittest.TestCase):
    def test_flags_reqeusts_with_weak_signal(self):
        [f] = typo("reqeusts", "pypi", downloads=12, created=DAYS_AGO(3))
        self.assertEqual((f.rule_id, f.severity, f.weight), ("TYPO001", "suspicious", 25))
        self.assertIn("`requests`", f.message)
        self.assertIn("1 edit", f.message)
        self.assertEqual(f.confidence, 0.9)

    def test_flags_homoglyph_variants(self):
        for name, ecosystem, imitated in (("rеquests", "pypi", "requests"),   # Cyrillic e
                                          ("rnoment", "npm", "moment"),          # rn -> m
                                          ("1odash", "npm", "lodash"),           # 1 -> l
                                          ("n0de-fetch", "npm", "node-fetch"),   # 0 -> o
                                          ("react_dom", "npm", "react-dom")):    # separator
            with self.subTest(name=name):
                [f] = typo(name, ecosystem, downloads=40)
                self.assertEqual((f.rule_id, f.severity), ("TYPO002", "suspicious"))
                self.assertIn(f"`{imitated}`", f.message)

    def test_preact_is_not_flagged(self):
        self.assertEqual(typo("preact"), [])                 # bundled popular name
        self.assertEqual(typo("preact", downloads=3), [])    # even with a weak signal

    def test_popular_lookalike_is_not_flagged(self):
        # a name 1 edit from `react` that is itself popular: similarity alone is never enough
        self.assertEqual(typo("reactr", downloads=5_000_000, created=DAYS_AGO(2)), [])
        self.assertEqual(typo("reqeusts", "pypi", downloads=150_000), [])

    def test_bundled_popular_names_never_flag(self):
        for ecosystem, names in typosquat.POPULAR_PACKAGES.items():
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(typo(name, ecosystem, downloads=1, created=DAYS_AGO(1)), [])

    def test_real_scoped_packages_are_not_flagged(self):
        for name in ("@types/node", "@types/reqeusts", "@babel/preset-env", "@angular/core",
                     "@aws-sdk/client-s3", "@acme/lodash", "@my-org/internal-tool"):
            with self.subTest(name=name):
                self.assertEqual(typo(name, downloads=3, created=DAYS_AGO(1)), [])

    def test_scope_squat_is_flagged(self):
        [f] = typo("@bable/core", downloads=3)
        self.assertEqual((f.rule_id, f.severity), ("TYPO003", "suspicious"))
        self.assertIn("`@babel`", f.message)

    def test_similarity_without_registry_data_is_info_and_scores_zero(self):
        [f] = typo("reqeusts", "pypi")
        self.assertEqual((f.severity, f.weight), ("info", 0))
        self.assertIn("unconfirmed: no registry data", f.message)
        self.assertEqual(finding_type(f), "typosquat_unconfirmed")
        verdict = build_verdict({"name": "reqeusts"}, [f])
        self.assertEqual((verdict["score"], verdict["band"]), (0, "safe"))

    def test_established_package_without_weak_signal_is_info(self):
        [f] = typo("axois", downloads=50_000, created=DAYS_AGO(3000))
        self.assertEqual(f.severity, "info")
        self.assertIn("established package", f.message)

    def test_distant_and_short_names(self):
        self.assertEqual(typo("requestsxx", "pypi", downloads=1), [])  # 2 edits from an 8-letter name
        self.assertEqual(typo("vuw", downloads=1), [])                  # too short to mean anything
        [f] = typo("matplotlb", "pypi", downloads=1)
        self.assertIn("`matplotlib`", f.message)
        [f] = typo("scikit-lern", "pypi", downloads=1)
        self.assertIn("`scikit-learn`", f.message)

    def test_hand_rolled_distance(self):
        d = typosquat.distance
        self.assertEqual([d("kitten", "sitting"), d("reqeusts", "requests"), d("", "abc"), d("same", "same")],
                         [3, 1, 3, 0])


class EndToEnd(unittest.TestCase):
    def test_typosquat_with_no_legitimacy_scores_malicious(self):
        meta = {"name": "reqeusts", "ecosystem": "pypi", "version": "0.0.1",
                "created": DAYS_AGO(2), "downloads": 9, "repo_url": "https://github.com/psf/requests"}
        with tempfile.TemporaryDirectory() as d:
            findings = run_scanner(d, meta)
        rules = sorted(f.rule_id for f in findings)
        self.assertEqual(rules, ["META001", "META002", "META004", "TYPO001"])
        verdict = build_verdict(meta, findings)
        self.assertEqual(verdict["band"], "malicious")
        self.assertTrue(any("typosquat with no legitimacy" in line for line in verdict["explanation"]))

    def test_legit_package_scores_nothing_from_identity_checks(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_scanner(d, LEGIT), [])


class FindingContract(unittest.TestCase):
    def test_positional_calls_still_work(self):
        f = Finding("glassworm", "suspicious", 30, "msg", "a.js:1")
        self.assertEqual((f.rule_id, f.category, f.confidence), ("", "", None))
        self.assertEqual(list(f.to_dict()), ["check", "severity", "weight", "message", "location",
                                             "rule_id", "category", "confidence"])

    def test_confidence_is_validated(self):
        with self.assertRaises(ValueError):
            Finding("x", "info", 0, "m", confidence=1.5)


class AcquisitionHistory(unittest.TestCase):
    def test_npm_previous_release_maintainers_feed_takeover_check(self):
        from app.acquisition.npm import history
        packument = {
            "time": {"created": "2019-01-01T00:00:00Z", "modified": "2026-10-30T00:00:00Z",
                     "1.0.0": "2019-01-01T00:00:00Z", "1.0.1": "2020-01-01T00:00:00Z",
                     "1.0.2": "2026-10-30T00:00:00Z"},
            "versions": {"1.0.1": {"maintainers": [{"name": "alice"}]}},
        }
        meta = {"name": "event-thing", "version": "1.0.2", "maintainers": ["mallory"],
                "downloads": 2_000_000, "repo_url": "https://github.com/a/event-thing"}
        history(packument, "1.0.2", meta)
        self.assertEqual((meta["created"], meta["previous_version"], meta["previous_maintainers"]),
                         ("2019-01-01T00:00:00Z", "1.0.1", ["alice"]))
        self.assertEqual([f.rule_id for f in metadata.check(Path(), meta)], ["META003"])

    def test_pypi_history(self):
        from app.acquisition.pypi import history
        meta = {"version": "2.0.0"}
        history({"1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
                 "1.5.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z"}],
                 "2.0.0": [{"upload_time_iso_8601": "2026-10-01T00:00:00Z"}],
                 "0.0.0": []}, meta)
        self.assertEqual((meta["created"], meta["previous_version"]), ("2020-01-01T00:00:00Z", "1.5.0"))
        history(None, meta)  # malformed -> untouched, no crash


if __name__ == "__main__":
    unittest.main()
