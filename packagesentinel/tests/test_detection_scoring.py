import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection import scoring  # noqa: E402
from app.detection.scanner import Finding  # noqa: E402
from app.detection.scoring import THRESHOLDS, build_verdict, finding_type, score  # noqa: E402


def F(check, message, severity="suspicious", weight=10, location="x.js:1"):
    return Finding(check, severity, weight, message, location)


SSH = F("credential_access", "References credential locations: SSH keys (~/.ssh)")
WEBHOOK = F("network_exfil", "Hard-coded Discord webhook: `https://discord.com/api/webhooks/1/x`")
HOOK = F("install_hooks", "postinstall runs `node setup.js`")
EVAL_B64 = F("obfuscation", "Decodes an encoded string and executes it (`eval(` + base64/hex decode)")
B64_CODE = F("obfuscation", "base64 string decodes to code: `require('x')`")
SPAWN = F("dangerous_call", "Runs a system command: `subprocess.run()`")
NETWORK = F("capability", "network: imports https (a.js)", "info", 0)
SQUAT = F("typosquat", "name `reqeusts` is one edit from `requests`")


class TypeMapping(unittest.TestCase):
    def test_real_scanner_messages_map_to_types(self):
        cases = [
            (SSH, "ssh_aws_read"), (WEBHOOK, "webhook_exfil"), (EVAL_B64, "eval_decoded"), (B64_CODE, "encoded_code"),
            (SPAWN, "process_spawn"), (NETWORK, "network_call"), (HOOK, "hook_exists"), (SQUAT, "typosquat"),
            (F("glassworm", "Hidden payload: 161 invisible ..."), "glassworm_unicode"),
            (F("trojan_source_bidi", "Trojan Source ..."), "trojan_source_bidi"),
            (F("stego", "154 bytes of code hidden after the PNG IEND chunk"), "stego_payload"),
            (F("credential_access", "References credential locations: .env file"), "dotenv_read"),
            (F("dynamic_fetch", "Mentions a download-and-run shell command: `x`"), "shell_mention"),
        ]
        for f, t in cases:
            with self.subTest(t=t):
                self.assertEqual(finding_type(f), t)

    def test_unknown_check_falls_back_to_its_own_weight(self):
        s, _, expl = score([F("brand_new_check", "something", weight=17)])
        self.assertEqual(s, 17)
        self.assertIn("brand_new_check", expl[0])


class Stages(unittest.TestCase):
    def test_each_type_counts_once(self):
        s, band, expl = score([SPAWN] * 50)
        self.assertEqual(s, scoring.WEIGHTS["process_spawn"])
        self.assertIn("(+49 more)", expl[0])

    def test_capabilities_are_capped_together(self):
        caps = [SSH, SPAWN, NETWORK, F("credential_access", "Reads secret-looking environment variables: X"),
                F("dangerous_call", "Dynamic code execution: `eval(`")]
        s, band, expl = score(caps)
        self.assertEqual(s, scoring.CLASS_CAPS["capability"])
        self.assertNotEqual(band, "malicious")
        self.assertTrue(any(line.startswith("-") and "cap" in line for line in expl))

    def test_combo_fires_only_when_all_present(self):
        _, _, expl = score([HOOK, SSH, WEBHOOK])
        self.assertTrue(any("credential stealer in installer" in line for line in expl))
        _, _, expl = score([HOOK, SSH])
        self.assertFalse(any("combo" in line for line in expl))

    def test_combo_groups(self):
        # encoded_code counts as "obfuscation" for the obfuscated-execution combo
        _, _, expl = score([EVAL_B64, B64_CODE])
        self.assertTrue(any("obfuscated payload execution" in line for line in expl))

    def test_popular_package_is_not_a_typosquat(self):
        s, _, expl = score([SQUAT], {"downloads": 5_000_000})
        self.assertEqual(s, 0)
        self.assertTrue(any("dampener" in line for line in expl))
        self.assertEqual(score([SQUAT], {"downloads": 40})[0], 25 + scoring.WEIGHTS["low_downloads"])

    def test_typosquat_with_no_legitimacy_combo_from_meta(self):
        new = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        s, band, expl = score([SQUAT], {"downloads": 12, "published": new})
        self.assertTrue(any("typosquat with no legitimacy" in line for line in expl))
        self.assertEqual(band, "malicious")

    def test_network_fits_purpose_dampener(self):
        self.assertEqual(score([NETWORK], {"name": "fast-http-client"})[0], 0)
        self.assertEqual(score([NETWORK], {"name": "left-pad"})[0], 10)
        # not softened when there is an exfil endpoint
        self.assertGreater(score([NETWORK, WEBHOOK], {"name": "http-client"})[0], 40)

    def test_clamp_and_bands(self):
        s, band, _ = score([F("glassworm", "Hidden payload: x"), F("stego", "code hidden after the PNG")])
        self.assertEqual((s, band), (100, "malicious"))
        self.assertEqual(score([])[:2], (0, "safe"))
        self.assertEqual(score([WEBHOOK])[1], "suspicious" if 40 < THRESHOLDS["malicious"] else "malicious")

    def test_severity_override_never_downgrades(self):
        weak = F("brand_new_check", "confirmed payload", severity="malicious", weight=1)
        s, band, expl = score([weak])
        self.assertEqual(band, "malicious")
        self.assertGreaterEqual(s, THRESHOLDS["malicious"])
        self.assertTrue(expl[-1].startswith("band forced"))


class Verdict(unittest.TestCase):
    def test_contract_fields_plus_explanation(self):
        v = build_verdict({"name": "p", "version": "1.0.0"}, [SSH, WEBHOOK])
        for key in ("package", "version", "score", "band", "findings", "capabilities", "mismatches"):
            self.assertIn(key, v)
        self.assertIsInstance(v["explanation"], list)


if __name__ == "__main__":
    unittest.main()
