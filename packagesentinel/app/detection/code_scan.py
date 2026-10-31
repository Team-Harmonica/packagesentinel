"""Parsed-code detectors (scanner group II).

Five detectors run over every Python and JavaScript/TypeScript file:

    dangerous_call     eval / exec / new Function / child_process / subprocess
    credential_access  ~/.ssh, ~/.aws, registry tokens, browser + wallet stores,
                       secret-looking env vars, bulk environment dumps
    network_exfil      Discord/Telegram webhooks, paste/tunnel hosts, raw-IP URLs,
                       and "reads secrets + talks to the network" in one file
    dynamic_fetch      download-then-execute (fetch -> eval, exec(urlopen()),
                       curl | sh)
    obfuscation        decode-then-execute, base64 that decodes to code,
                       large opaque blobs, obfuscator-style identifiers

Python is parsed with the stdlib `ast` (real call resolution, import aliases).
JavaScript uses a small lexer that strips comments and separates string
literals from code, so `// eval(x)` and `"eval is evil"` never match a sink.

Every file also reports which capabilities it uses (network / process /
filesystem / env / dynamic-code). These become one weight-0 `capability` finding per bucket for the
compatibility profile.

scan_source() is the single-text entry point; glassworm uses it to rescan
payloads decoded from invisible Unicode, and this module uses it recursively
on base64 blobs that decode to code.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bisect
import ipaddress
import math
import re
import warnings
from collections import Counter
from pathlib import Path

from .scanner import Finding, iter_files, rel

PY_EXT = {".py", ".pyw"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
MAX_DEPTH = 2  # recursion limit for "this blob decodes to code, scan it too"


def _severity(weight: int) -> str:
    return "malicious" if weight >= 40 else "suspicious" if weight >= 10 else "info"


class Report:
    """Collects findings for one piece of source, deduplicating repeats."""

    def __init__(self, origin: str, text: str, line_numbers: bool = True):
        self.origin = origin
        self.text = text
        self.line_numbers = line_numbers
        self._starts: list[int] | None = None
        self._items: dict[tuple, list] = {}
        self.extra: list[Finding] = []  # findings from recursively scanned blobs
        self.signals: set[str] = set()
        self.capabilities: dict[str, str] = {}  # bucket -> first piece of evidence
        self.opaque: list[tuple[int, int]] = []  # (line, length) of undecodable blobs

    def line_of(self, offset: int) -> int:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer("\n", self.text)]
        return bisect.bisect_right(self._starts, offset)

    def loc(self, line: int | None) -> str:
        return f"{self.origin}:{line}" if self.line_numbers and line else self.origin

    def add(self, check: str, weight: int, message: str, line: int | None = None) -> None:
        key = (check, message)
        if key in self._items:
            self._items[key][1] += 1
        else:
            self._items[key] = [Finding(check, _severity(weight), weight, message, self.loc(line)), 1]

    def cap(self, bucket: str, evidence: str) -> None:
        self.capabilities.setdefault(bucket, evidence)

    def findings(self) -> list[Finding]:
        out = []
        for f, n in self._items.values():
            if n > 1:
                f.message += f" (x{n})"
            out.append(f)
        return out + self.extra


# --- string-level detectors (shared by both languages) ----------------------

CREDENTIAL_TARGETS = [
    (re.compile(r"(?:^|[/\\~])\.ssh(?:[/\\]|$)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"), "SSH keys (~/.ssh)", 20),
    (re.compile(r"(?:^|[/\\~])\.aws(?:[/\\]|$)"), "AWS credentials (~/.aws)", 20),
    (re.compile(r"(?:^|[/\\~])\.(?:npmrc|pypirc|netrc|git-credentials)$"), "registry / git tokens", 20),
    (re.compile(r"\.docker[/\\]config\.json|\.kube[/\\]config"), "Docker / Kubernetes credentials", 20),
    (re.compile(r"[/\\](?:Login Data|Cookies|Local State|key4\.db|logins\.json)$"),
     "browser passwords / cookies", 25),
    (re.compile(r"wallet\.dat|[/\\](?:Exodus|Electrum|atomic)[/\\]|nkbihfbeogaeaoehlefnkodbefgpgknn"
                r"|\.config[/\\]solana"), "crypto wallets", 25),
    (re.compile(r"\.(?:bash|zsh)_history$"), "shell history", 15),
    (re.compile(r"(?:^|[/\\])\.env$"), ".env file", 5),
]

EXFIL_ENDPOINTS = [
    (re.compile(r"discord(?:app)?\.com/api/webhooks/|/api/webhooks/\d{6,}/[\w-]{20,}", re.I),
     "Discord webhook", 35),
    (re.compile(r"api\.telegram\.org/bot|/bot\d{5,}:[\w-]{20,}"), "Telegram bot API", 35),
    (re.compile(r"\b(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|transfer\.sh|webhook\.site"
                r"|requestbin\.\w+|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com"
                r"|loca\.lt|serveo\.net|burpcollaborator\.net|interact\.sh"
                r"|oast\.(?:fun|pro|live|site|me|online)|canarytokens\.com)\b", re.I),
     "paste / tunnel / request-catcher host", 25),
]
RAW_IP_URL = re.compile(r"\b(?:https?|wss?|ftp|tcp)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?", re.I)
SHELL_FETCH_RUN = re.compile(
    r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\s+[^|\n]{1,200}\|\s*(?:iex|Invoke-Expression)\b"
    r"|\b(?:iex|Invoke-Expression)\s*\(?\s*(?:\(\s*New-Object\s+(?:System\.)?Net\.WebClient\s*\)\s*\.\s*"
    r"DownloadString|(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\s)"
    r"|powershell[^\n]*\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}",
    re.I,
)
SMALL_FILE = 100_000  # "same file" co-occurrence only means something in files this size
B64_STRING = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$|^[A-Za-z0-9_-]{40,}={0,2}$")
HEX_STRING = re.compile(r"^(?:[0-9a-fA-F]{2}){100,}$")
MEDIA_MAGIC = (b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"wOFF", b"wOF2", b"\x00\x01\x00\x00",
               b"OTTO", b"<svg", b"<?xml", b"RIFF", b"\x00\x00\x01\x00")
CODE_TOKENS = re.compile(
    r"require\s*\(|\bimport\s|\beval\s*\(|Function\s*\(|\bexec\w*\s*\(|child_process|subprocess"
    r"|os\.system|__import__|process\.env|=>|\bfunction\b|\b(?:const|let|var)\s|https?://"
    r"|\bdef\s+\w+\s*\(|console\.\w+\s*\("
)


def _entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _readable(s: str) -> bool:
    return len(s.strip()) >= 8 and sum(ch.isprintable() or ch in "\n\r\t" for ch in s) / len(s) >= 0.9


def _public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    private = any(ip in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    return not (private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)


def _b64decode(s: str) -> bytes | None:
    try:
        if "-" in s or "_" in s:
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _scan_strings(rep: Report, strings: list[tuple[str, int]], depth: int) -> None:
    creds: dict[str, tuple[int, int]] = {}  # label -> (weight, line)
    for value, line in strings:
        if not value or len(value) > 200_000:
            continue

        if not _is_prose(value):
            for pattern, label, weight in CREDENTIAL_TARGETS:
                if any(pattern.search(tok) for tok in _path_tokens(value)) and label not in creds:
                    creds[label] = (weight, line)

        for pattern, label, weight in EXFIL_ENDPOINTS:
            if pattern.search(value):
                rep.add("network_exfil", weight, f"Hard-coded {label}: `{_short(value)}`", line)
                rep.signals.add("exfil_endpoint")
                rep.cap("network", label)
        for m in RAW_IP_URL.finditer(value):
            if _public_ip(m.group(1)):
                rep.add("network_exfil", 20, f"URL with a raw public IP address: `{_short(m.group())}`", line)
                rep.signals.add("exfil_endpoint")
                rep.cap("network", "raw IP URL")

        if SHELL_FETCH_RUN.search(value):
            if "process" in rep.capabilities:
                rep.add("dynamic_fetch", 45, f"Shell command downloads and runs code: `{_short(value)}`", line)
            else:  # install instructions shown to a user, security deny-lists, docs
                rep.add("dynamic_fetch", 5, f"Mentions a download-and-run shell command: `{_short(value)}`", line)

        _scan_blob(rep, value, line, depth)

    if creds:
        labels = sorted(creds, key=lambda k: -creds[k][0])
        weight = min(35, max(w for w, _ in creds.values()) + 5 * (len(creds) - 1))
        rep.add("credential_access", weight, f"References credential locations: {', '.join(labels)}",
                creds[labels[0]][1])
        if any(w >= 15 for w, _ in creds.values()):
            rep.signals.add("credential_read")
        rep.cap("filesystem", f"reads {labels[0]}")


SHELL_WORDS = {"cat", "cp", "mv", "tar", "zip", "scp", "rsync", "curl", "wget", "base64", "type", "copy",
               "find", "grep", "nc", "powershell", "cmd", "sh", "bash"}


def _is_prose(value: str) -> bool:
    """A sentence that mentions a path ("no key in ~/.ssh") rather than a path or a command."""
    words = value.split()
    return (len(words) >= 4 and words[0].lower() not in SHELL_WORDS
            and not any(c in value for c in ("|", ">", "<", "$(", "`", "&&")))


def _path_tokens(value: str) -> list[str]:
    # "~/.ssh/id_rsa" stays whole; "cat ~/.ssh/id_rsa | curl …" is split into words
    return value.split() if " " in value.strip() else [value]


def _scan_blob(rep: Report, value: str, line: int, depth: int) -> None:
    """Base64 / hex / high-entropy strings: what is this, and is it code?"""
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 40 or compact.startswith("data:"):
        return

    data = None
    if B64_STRING.match(compact):
        data, kind = _b64decode(compact), "base64"
    elif HEX_STRING.match(compact):
        data, kind = bytes.fromhex(compact), "hex"
    if data is not None:
        if data.startswith(MEDIA_MAGIC):
            return  # embedded image / font
        text = data.decode("utf-8", errors="replace")
        if _readable(text) and CODE_TOKENS.search(text):
            rep.add("obfuscation", 30, f"{kind} string decodes to code: `{_short(text)}`", line)
            rep.signals.add("encoded_code")
            if depth < MAX_DEPTH:
                for f in scan_source(text, rep.loc(line), line_numbers=False, _depth=depth + 1):
                    f.message = f"[inside {kind} blob] {f.message}"
                    rep.extra.append(f)
            return
        if len(compact) >= 1000:
            rep.opaque.append((line, len(compact)))
        return

    if len(compact) >= 300 and " " not in value and compact.isascii() and _entropy(compact) >= 5.0:
        rep.opaque.append((line, len(compact)))


def _short(s: str, limit: int = 90) -> str:
    s = "".join(ch if ch.isprintable() else f"\\u{{{ord(ch):X}}}" for ch in s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


SECRET_ENV = re.compile(
    r"^(?:AWS_\w+|NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN|PYPI_TOKEN"
    r"|TWINE_PASSWORD|SLACK_TOKEN|DISCORD_TOKEN|\w*(?:_SECRET|_PASSWORD|_PASSWD|PRIVATE_KEY|API_KEY"
    r"|ACCESS_KEY|_TOKEN))$"
)


def _finish(rep: Report, secret_env: dict[str, int]) -> None:
    """Per-file combinations that only make sense with the whole file in view."""
    if secret_env:
        names = sorted(secret_env)
        shown = ", ".join(names[:5]) + (f" +{len(names) - 5} more" if len(names) > 5 else "")
        rep.add("credential_access", 10, f"Reads secret-looking environment variables: {shown}",
                min(secret_env.values()))
        rep.signals.add("env_secret")
        rep.cap("env", names[0])

    if rep.opaque:
        rep.add("obfuscation", 3, f"{len(rep.opaque)} large opaque string(s) (biggest "
                                  f"{max(n for _, n in rep.opaque)} chars): embedded data or packed payload",
                rep.opaque[0][0])

    secrets = rep.signals & {"credential_read", "env_bulk", "env_secret"}
    if secrets and "exfil_endpoint" in rep.signals:
        rep.add("network_exfil", 50, "Reads credentials/secrets AND contains an exfiltration endpoint "
                                     "in the same file: the shape of a credential stealer")
    elif secrets - {"env_secret"} and "network" in rep.capabilities and len(rep.text) < SMALL_FILE:
        rep.add("network_exfil", 25, "Reads credential files or dumps the environment, and can send "
                                     "data over the network from the same file")


# --- JavaScript -------------------------------------------------------------

JS_TOKEN = re.compile(
    r"""(?P<lc>//[^\n]*)
      | (?P<bc>/\*.*?(?:\*/|\Z))
      | (?P<s>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
      | (?P<t>`(?:\\.|[^`\\])*`)
      | (?<=[(,=:!&|?;{}\[])(?P<re>\s*/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+/[a-z]*)
    """,
    re.S | re.X,
)
JS_ESCAPE = re.compile(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r?\n|.)", re.S)
JS_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _js_unescape(s: str) -> str:
    if "\\" not in s:
        return s

    def repl(m: re.Match) -> str:
        e = m.group(1)
        if e[0] == "u" and len(e) > 1:
            cp = int(e[2:-1] if e[1] == "{" else e[1:], 16)
            return chr(cp) if cp <= 0x10FFFF else ""
        if e[0] == "x" and len(e) == 3:
            return chr(int(e[1:], 16))
        if e in ("\n", "\r\n"):
            return ""
        return JS_SIMPLE_ESC.get(e, e)

    return JS_ESCAPE.sub(repl, s)


def _blank(s: str) -> str:
    return re.sub(r"[^\n]", " ", s)


def js_lex(text: str) -> tuple[str, list[tuple[str, int]]]:
    """Return (code with comments/strings/regexes blanked, [(string value, offset)]).

    Blanking keeps every offset and newline in place, so positions found in
    the blanked code map straight back to lines in the original file.
    """
    parts, strings, last = [], [], 0
    for m in JS_TOKEN.finditer(text):
        start, end = m.span()
        parts.append(text[last:start])
        tok = m.group()
        if m.lastgroup in ("s", "t"):
            strings.append((_js_unescape(tok[1:-1]), start))
            parts.append(tok[0] + _blank(tok[1:-1]) + tok[-1])
        else:
            parts.append(_blank(tok))
        last = end
    parts.append(text[last:])
    return "".join(parts), strings


JS_EVAL = re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\("
                     r"|\bvm\s*\.\s*(?:runIn\w+|compileFunction)\s*\(|\bnew\s+vm\s*\.\s*Script\s*\("
                     r"|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]")
JS_PROC_CALL = re.compile(r"(?<![\w$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(")
JS_NET_CALL = re.compile(r"(?<![\w$.])fetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|sendBeacon\s*\("
                         r"|\b(?:https?|net|tls|dgram|axios|got|request|needle)\s*\.\s*"
                         r"(?:get|post|put|request|connect|createConnection|createSocket)\s*\(")
JS_FETCH_THEN_RUN = re.compile(r"\.then\s*\(\s*(?:eval|Function|new\s+Function)\b")
JS_DECODE = re.compile(r"\batob\s*\(|Buffer\s*\.\s*from\s*\(|\bdecodeURIComponent\s*\(\s*escape\b")
JS_ENV_NAME = re.compile(r"process\s*\.\s*env\s*\.\s*([A-Za-z_]\w*)")
JS_ENV_INDEX = re.compile(r"process\s*\.\s*env\s*\[\s*[\"'`]")
JS_ENV_DUMP = re.compile(r"JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\s*[,)]")
JS_ENV_ENUM = re.compile(r"Object\s*\.\s*(?:keys|values|entries)\s*\(\s*process\s*\.\s*env\s*\)")
JS_OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
JS_IMPORT_BEFORE = re.compile(r"(?:\brequire\s*\(|\bimport\s*\(|\bfrom)\s*$")
JS_BRACKET_BEFORE = re.compile(r"[\w$)\]]\s*\[\s*$")  # obj["eval"], not an array literal ["eval", …]
JS_CALL_AFTER = re.compile(r"\s*\]\s*\(")

NET_MODULES = {"http", "https", "net", "tls", "dgram", "axios", "node-fetch", "got", "request",
               "undici", "ws", "needle", "superagent"}
FS_MODULES = {"fs", "fs/promises", "fs-extra", "graceful-fs"}


def _scan_js(rep: Report, text: str, depth: int) -> None:
    code, raw_strings = js_lex(text)
    starts = {off: val for val, off in raw_strings}
    strings = [(val, rep.line_of(off)) for val, off in raw_strings]

    modules: dict[str, int] = {}
    for val, off in raw_strings:
        before = code[max(0, off - 30):off]
        if JS_IMPORT_BEFORE.search(before):
            modules.setdefault(val.removeprefix("node:"), off)
        elif (val in ("eval", "Function", "execSync", "exec") and JS_BRACKET_BEFORE.search(before)
              and JS_CALL_AFTER.match(code, code.index(code[off], off + 1) + 1)):
            rep.add("obfuscation", 20, f"`{val}` looked up by string name (`[\"{val}\"]`) to dodge "
                                       "static detection", rep.line_of(off))

    if any(m in NET_MODULES for m in modules):
        rep.cap("network", "imports " + next(m for m in modules if m in NET_MODULES))
    if any(m in FS_MODULES for m in modules):
        rep.cap("filesystem", "imports fs")
    if "child_process" in modules:
        rep.cap("process", "imports child_process")
        for m in JS_PROC_CALL.finditer(code):
            rep.add("dangerous_call", 15, f"Spawns a process via child_process "
                                          f"(`{m.group().rstrip('( ')}`)", rep.line_of(m.start()))

    net_calls = [m.start() for m in JS_NET_CALL.finditer(code)]
    if net_calls:
        rep.cap("network", "makes HTTP/socket calls")

    sinks = []
    for m in JS_EVAL.finditer(code):
        # skip the ubiquitous globalThis polyfill: Function("return this")()
        paren = code.find("(", m.start())
        nxt = paren + 1 + len(code[paren + 1:]) - len(code[paren + 1:].lstrip())
        if starts.get(nxt) == "return this":
            continue
        sinks.append(m)
        rep.cap("dynamic-code", m.group().rstrip("( \"'`"))
    for m in sinks:
        line = rep.line_of(m.start())
        window = code[m.end():m.end() + 160]
        win_strings = [v for o, v in starts.items() if m.end() <= o < m.end() + 160]
        if JS_DECODE.search(window) and ("atob" in window or any(v in ("base64", "hex") for v in win_strings)):
            rep.add("obfuscation", 45, f"Decodes an encoded string and executes it "
                                       f"(`{m.group().strip()}` + base64/hex decode)", line)
        elif any(abs(m.start() - n) <= 200 for n in net_calls):
            rep.add("dynamic_fetch", 30, f"Network call right next to dynamic code execution "
                                         f"(`{m.group().strip()}`): may run downloaded code", line)
        else:
            rep.add("dangerous_call", 10, f"Dynamic code execution: `{m.group().strip()}`", line)
    for m in JS_FETCH_THEN_RUN.finditer(code):
        rep.add("dynamic_fetch", 50, "Response of a network request is passed straight to eval/Function",
                rep.line_of(m.start()))
    if sinks and net_calls and len(text) < SMALL_FILE \
            and not any(f.check == "dynamic_fetch" for f, _ in rep._items.values()):
        rep.add("dynamic_fetch", 20, "Same file both downloads content and runs dynamic code",
                rep.line_of(sinks[0].start()))

    secret_env: dict[str, int] = {}
    for m in JS_ENV_NAME.finditer(code):
        rep.cap("env", f"process.env.{m.group(1)}")
        if SECRET_ENV.match(m.group(1)):
            secret_env.setdefault(m.group(1), rep.line_of(m.start()))
    for m in JS_ENV_INDEX.finditer(code):
        name = starts.get(m.end() - 1, "")
        if SECRET_ENV.match(name):
            secret_env.setdefault(name, rep.line_of(m.start()))
    for m in JS_ENV_DUMP.finditer(code):
        rep.add("credential_access", 15, "Serializes the entire environment (`JSON.stringify(process.env)`)",
                rep.line_of(m.start()))
        rep.signals.add("env_bulk")
        rep.cap("env", "whole environment")
    for m in JS_ENV_ENUM.finditer(code):
        rep.add("credential_access", 5, "Enumerates every environment variable", rep.line_of(m.start()))
        rep.cap("env", "whole environment")

    obf = len(set(JS_OBF_IDENT.findall(code)))
    if obf >= 15:
        rep.add("obfuscation", 20, f"{obf} javascript-obfuscator style identifiers (`_0x1a2b`)")
    hex_escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", text))
    if hex_escapes >= 200 and hex_escapes * 4 >= 0.2 * len(text):
        rep.add("obfuscation", 15, f"{hex_escapes} hex escapes make up "
                                   f"{hex_escapes * 400 // len(text)}% of the file (string-encoding obfuscator)")

    _scan_strings(rep, strings, depth)
    _finish(rep, secret_env)


# --- Python -----------------------------------------------------------------

PY_EXEC = {"eval", "exec", "builtins.eval", "builtins.exec"}
PY_PROC_EXACT = {"os.system", "os.popen", "pty.spawn", "commands.getoutput", "os.startfile"}
PY_PROC_PREFIX = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn")
PY_NOT_PROC = {"subprocess.CalledProcessError", "subprocess.TimeoutExpired",
               "subprocess.CompletedProcess", "subprocess.SubprocessError"}
PY_NET_PREFIX = ("urllib.request.", "urllib2.", "urllib.urlopen", "requests.", "httpx.", "http.client.",
                 "aiohttp.", "urllib3.", "socket.", "ftplib.", "smtplib.", "websocket.")
PY_DECODE = {"base64.b64decode", "base64.b32decode", "base64.b85decode", "base64.a85decode",
             "base64.decodebytes", "base64.urlsafe_b64decode", "binascii.unhexlify", "binascii.a2b_base64",
             "bytes.fromhex", "codecs.decode", "zlib.decompress", "gzip.decompress", "lzma.decompress",
             "bz2.decompress", "marshal.loads"}
PY_FS = ("open", "io.open", "os.remove", "os.unlink", "shutil.", "os.makedirs", "pathlib.")


class _PyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.alias: dict[str, str] = {}
        self.calls: list[tuple[str, ast.Call]] = []
        self.strings: list[tuple[str, int]] = []
        self.env_reads: list[tuple[str, int]] = []
        self.modules: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.modules.add(a.name)
            if a.asname:
                self.alias[a.asname] = a.name
            else:
                top = a.name.split(".")[0]
                self.alias[top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.modules.add(node.module)
            for a in node.names:
                self.alias[a.asname or a.name] = f"{node.module}.{a.name}"

    def qual(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):  # __import__("os").system
            f = self.qual(node.func)
            if f in ("__import__", "importlib.import_module") and node.args \
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                self.modules.add(node.args[0].value)
                return node.args[0].value
        return None

    def visit_Call(self, node: ast.Call) -> None:
        q = self.qual(node.func)
        if q:
            self.calls.append((q, node))
            if q in ("os.getenv", "os.environ.get") and node.args and isinstance(node.args[0], ast.Constant):
                self.env_reads.append((str(node.args[0].value), node.lineno))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.qual(node.value) == "os.environ" and isinstance(node.slice, ast.Constant):
            self.env_reads.append((str(node.slice.value), node.lineno))
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        # docstrings and bare string statements are documentation, not data
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.strings.append((node.value, node.lineno))
        elif isinstance(node.value, bytes):
            self.strings.append((node.value.decode("latin-1"), node.lineno))


def _split_literal(node: ast.AST) -> bool:
    """'sys' + 'tem' or f'{"sys"}tem': a constant string deliberately written in pieces."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = [node.left, node.right]
        return all(isinstance(p, ast.Constant) and isinstance(p.value, str) or _split_literal(p) for p in parts)
    return False


def _is_net(q: str) -> bool:
    return q.startswith(PY_NET_PREFIX) or q == "urlopen"


def _scan_python(rep: Report, text: str, depth: int) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        _scan_python_fallback(rep, text, depth)
        return
    v = _PyVisitor()
    v.visit(tree)

    if any(m.split(".")[0] in ("socket", "requests", "httpx", "urllib", "urllib2", "urllib3", "aiohttp",
                               "http", "ftplib", "smtplib", "websocket") for m in v.modules):
        rep.cap("network", "imports " + sorted(v.modules)[0])

    for q, node in v.calls:
        line = node.lineno
        if q in PY_EXEC:
            rep.cap("dynamic-code", q)
            arg = node.args[0] if node.args else None
            inner = [v.qual(n.func) or "" for n in ast.walk(arg) if isinstance(n, ast.Call)] if arg else []
            if arg is None or (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                rep.add("dangerous_call", 2, f"`{q}()` of a literal string", line)
            elif any(_is_net(i) for i in inner):
                rep.add("dynamic_fetch", 50, f"Downloads code and executes it: `{q}({_first(inner, _is_net)}(…))`", line)
            elif any(i in PY_DECODE for i in inner):
                rep.add("obfuscation", 45, f"Decodes and executes hidden code: "
                                           f"`{q}({_first(inner, PY_DECODE.__contains__)}(…))`", line)
            else:
                rep.add("dangerous_call", 10, f"Dynamic code execution: `{q}()` on a computed value", line)
        elif q in PY_PROC_EXACT or (q.startswith(PY_PROC_PREFIX) and q not in PY_NOT_PROC):
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value
                        for k in node.keywords)
            rep.add("dangerous_call", 15, f"Runs a system command: `{q}()`" + (" with shell=True" if shell else ""), line)
            rep.cap("process", q)
        elif _is_net(q):
            rep.cap("network", q)
        elif q in ("json.dumps", "str", "repr", "print") and any(v.qual(a) == "os.environ" for a in node.args):
            rep.add("credential_access", 15, f"Serializes the entire environment (`{q}(os.environ)`)", line)
            rep.signals.add("env_bulk")
            rep.cap("env", "whole environment")
        elif q in ("os.environ.items", "os.environ.keys", "os.environ.values"):
            rep.add("credential_access", 5, "Enumerates every environment variable", line)
            rep.cap("env", "whole environment")
        elif q == "getattr" and len(node.args) >= 2 and _split_literal(node.args[1]):
            rep.add("obfuscation", 20, f"Attribute name split into literal pieces to dodge grep "
                                       f"(`getattr(…, {ast.unparse(node.args[1])})`)", line)
        elif q.startswith(PY_FS):
            rep.cap("filesystem", q)

    secret_env: dict[str, int] = {}
    for name, line in v.env_reads:
        rep.cap("env", name)
        if SECRET_ENV.match(name):
            secret_env.setdefault(name, line)

    if len(re.findall(r"\bchr\(\s*\d+\s*\)", text)) >= 30:
        rep.add("obfuscation", 15, "Builds strings from long chains of chr() calls")

    _scan_strings(rep, v.strings, depth)
    _finish(rep, secret_env)


def _first(items: list[str], pred) -> str:
    return next(i for i in items if pred(i))


def _scan_python_fallback(rep: Report, text: str, depth: int) -> None:
    """Unparseable Python (py2, templated): regex over a comment-stripped view."""
    code = re.sub(r"#[^\n]*", "", text)
    for m in re.finditer(r"\b(?:exec|eval)\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\s*\(", code):
        rep.add("dangerous_call", 10, f"`{m.group().rstrip('( ')}` (file did not parse; regex match)",
                rep.line_of(m.start()))
    _, raw = js_lex(code)  # quoting rules are close enough to pull the string literals out
    _scan_strings(rep, [(val, rep.line_of(off)) for val, off in raw], depth)
    _finish(rep, {})


# --- entry points -----------------------------------------------------------


def guess_language(text: str) -> str:
    if re.search(r"require\s*\(|=>|\b(?:const|let|var)\s|\bfunction\b|console\.|;\s*$", text, re.M):
        return "js"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ast.parse(text)
        return "python"
    except (SyntaxError, ValueError):
        return "js"


def _language_of(path: Path, head: str) -> str | None:
    suffix = path.suffix.lower()
    if suffix in PY_EXT:
        return "python"
    if suffix in JS_EXT:
        return "js"
    if head.startswith("#!"):
        first = head.split("\n", 1)[0]
        return "python" if "python" in first else "js" if "node" in first else None
    return None


def _scan(text: str, origin: str, language: str | None, line_numbers: bool, depth: int) -> Report:
    rep = Report(origin, text, line_numbers)
    (_scan_python if (language or guess_language(text)) == "python" else _scan_js)(rep, text, depth)
    return rep


def scan_source(text: str, origin: str, language: str | None = None,
                line_numbers: bool = True, _depth: int = 0) -> list[Finding]:
    """Scan one piece of source text.

    `origin` becomes Finding.location (with `:line` appended unless
    line_numbers=False, which is what you want for decoded payloads).
    `language` is "python" or "js"; guessed when None.
    """
    return _scan(text, origin, language, line_numbers, _depth).findings()


def check(pkg_dir: Path, meta: dict) -> list[Finding]:
    pkg_dir = Path(pkg_dir)
    findings: list[Finding] = []
    capabilities: dict[str, list[tuple[str, str]]] = {}
    for path in iter_files(pkg_dir):
        try:
            text = path.read_bytes().decode("utf-8", errors="surrogateescape")
        except OSError:
            continue
        language = _language_of(path, text[:200])
        if not language or "\x00" in text[:8192]:
            continue
        relpath = rel(path, pkg_dir)
        rep = _scan(text, relpath, language, True, 0)
        findings.extend(rep.findings())
        for bucket, evidence in rep.capabilities.items():
            capabilities.setdefault(bucket, []).append((relpath, evidence))

    for bucket, uses in sorted(capabilities.items()):
        files = ", ".join(f for f, _ in uses[:3]) + (f" +{len(uses) - 3} more" if len(uses) > 3 else "")
        findings.append(Finding("capability", "info", 0, f"{bucket}: {uses[0][1]} ({files})", uses[0][0]))
    return findings
