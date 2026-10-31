"""Offline package-name typo detection against curated popular package names.

Similarity alone is never enough (popularity guard):
  * the package is itself popular (> POPULAR_DOWNLOADS)   -> no finding
  * similar AND a weak signal (new / low downloads)        -> suspicious, 25
  * similar, but no registry data or no weak signal         -> info, 0 points ("unconfirmed")

    TYPO001  name within a small edit distance of a popular package
    TYPO002  name made of lookalike characters (Cyrillic, rn->m, 0->o, 1->l, separators)
    TYPO003  npm scope imitating a well-known scope (@bable/core vs @babel)

Names in the bundled list, and packages under a well-known npm scope (only that
org can publish there), are never reported.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from .metadata import has_registry_data, is_popular, weak_signals
from .scanner import Finding

POPULAR_PACKAGES = {
    "npm": frozenset({
        "@babel/core", "@types/node", "@types/react", "@angular/core", "@vue/cli",
        "ajv", "angular", "ansi-regex", "async", "autoprefixer", "aws-sdk", "axios",
        "bcrypt", "bcryptjs", "bluebird", "body-parser", "bootstrap", "chai", "chalk",
        "chart.js", "cheerio", "classnames", "color", "colors", "commander", "concurrently",
        "core-js", "cors", "cross-env", "crypto-js", "date-fns", "dayjs", "debug",
        "discord.js", "dotenv", "electron", "esbuild", "eslint", "ethers", "event-stream",
        "express", "fast-glob", "fastify", "firebase", "form-data", "fs-extra", "glob",
        "graphql", "helmet", "husky", "immer", "inquirer", "ioredis", "jest", "jquery",
        "js-yaml", "jsonwebtoken", "koa", "less", "lodash", "minimatch", "minimist",
        "mkdirp", "mocha", "moment", "mongodb", "mongoose", "morgan", "mysql", "mysql2",
        "nanoid", "next", "node-fetch", "node-ipc", "nodemon", "nuxt", "open", "parcel",
        "picomatch", "pm2", "postcss", "preact", "prettier", "prop-types", "puppeteer",
        "ramda", "react", "react-dom", "react-native", "react-redux", "react-router",
        "react-router-dom", "redux", "request", "rimraf", "rollup", "rxjs", "sass",
        "semver", "sequelize", "serve", "sinon", "socket.io", "styled-components",
        "superagent", "supports-color", "svelte", "tailwindcss", "three", "tslib",
        "typescript", "ua-parser-js", "underscore", "uuid", "vite", "vue", "web3",
        "webpack", "webpack-cli", "yargs", "yarn", "zod",
    }),
    "pypi": frozenset({
        "aiohttp", "anthropic", "attrs", "awscli", "beautifulsoup4", "black", "boto3",
        "botocore", "celery", "certifi", "charset-normalizer", "chardet", "click",
        "colorama", "coverage", "cryptography", "dask", "discord.py", "django",
        "docutils", "fastapi", "filelock", "flake8", "flask", "grpcio", "gunicorn",
        "httpx", "idna", "ipython", "isort", "jinja2", "jsonschema", "jupyter", "keras",
        "lightgbm", "lxml", "markupsafe", "matplotlib", "mypy", "networkx", "nltk",
        "notebook", "numpy", "openai", "opencv-python", "orjson", "packaging", "pandas",
        "paramiko", "pillow", "pip", "platformdirs", "polars", "protobuf", "psycopg2",
        "psycopg2-binary", "pyarrow", "pydantic", "pygame", "pyjwt", "pylint", "pymongo",
        "pymysql", "pyopenssl", "pytest", "python-dateutil", "python-dotenv", "pytz",
        "pyyaml", "redis", "requests", "rich", "s3transfer", "scikit-learn", "scipy",
        "scrapy", "seaborn", "selenium", "setuptools", "simplejson", "six", "spacy",
        "sphinx", "sqlalchemy", "starlette", "sympy", "tensorflow", "toml", "tomli",
        "torch", "torchvision", "tqdm", "transformers", "typing-extensions", "tzdata",
        "ujson", "urllib3", "uvicorn", "virtualenv", "websocket-client", "websockets",
        "werkzeug", "wheel", "xgboost",
    }),
}

# npm scopes owned by a known organization: only that org can publish under
# them, so a name inside one is not an impersonation; a scope one edit away is.
KNOWN_SCOPES = frozenset({
    "angular", "apollo", "astrojs", "aws-amplify", "aws-cdk", "aws-sdk", "azure", "babel",
    "capacitor", "chakra-ui", "changesets", "commitlint", "discordjs", "docusaurus",
    "emotion", "eslint", "esbuild", "expo", "fastify", "firebase", "floating-ui",
    "fortawesome", "google-cloud", "graphql-tools", "headlessui", "heroicons", "ionic",
    "jest", "mantine", "mdx-js", "microsoft", "mui", "nestjs", "next", "nrwl", "nuxt",
    "octokit", "opentelemetry", "playwright", "popperjs", "prisma", "radix-ui",
    "react-native", "react-navigation", "reduxjs", "remix-run", "rollup", "sentry",
    "solana", "storybook", "stripe", "supabase", "sveltejs", "swc", "tailwindcss",
    "tanstack", "testing-library", "trpc", "types", "typescript-eslint", "vercel",
    "vitejs", "vue",
})

_CONFUSABLES = str.maketrans({
    "а": "a",  # Cyrillic
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "ѕ": "s",
    "і": "i",
    "ӏ": "l",
    "у": "y",
    "α": "a",  # Greek
    "ο": "o",
    "ρ": "p",
    "υ": "u",
    "χ": "x",
    "0": "o",       # ASCII lookalikes
    "1": "l",
})
# Multi-letter lookalikes, folded after the single-character map
_FOLDS = (("rn", "m"), ("vv", "w"))

MIN_NAME = 4        # shorter names are too close to everything to be meaningful
LONG_NAME = 10      # names this long may be up to 2 edits away


def _normalize(name: str, ecosystem: str) -> str:
    normalized = unicodedata.normalize("NFKC", name).casefold()
    if ecosystem == "pypi":
        normalized = re.sub(r"[-_.]+", "-", normalized)
    return normalized


def _skeleton(name: str, ecosystem: str) -> str:
    """What a name looks like to a human: lookalikes and separators folded."""
    folded = _normalize(name, ecosystem).translate(_CONFUSABLES)
    folded = re.sub(r"[-_.]+", "-", folded)
    for seq, repl in _FOLDS:
        folded = folded.replace(seq, repl)
    return folded


def distance(left: str, right: str) -> int:
    """Levenshtein distance with adjacent transpositions counted as one edit
    (optimal string alignment)."""
    if left == right:
        return 0
    prev2: list[int] = []
    prev = list(range(len(right) + 1))
    for i, a in enumerate(left, 1):
        cur = [i] + [0] * len(right)
        for j, b in enumerate(right, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a != b))
            if i > 1 and j > 1 and a == right[j - 2] and left[i - 2] == b:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def _max_distance(reference: str) -> int:
    return 2 if len(reference) >= LONG_NAME else 1


def _candidate(meta: dict) -> tuple[str, str] | None:
    ecosystem_value = meta.get("ecosystem")
    ecosystem = getattr(ecosystem_value, "value", ecosystem_value)
    if not isinstance(ecosystem, str) or ecosystem not in POPULAR_PACKAGES:
        return None

    name = meta.get("package_name") or meta.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    return ecosystem, name.strip()


def _closest(name: str, references, ecosystem: str) -> tuple[str, int, bool] | None:
    """(reference, edit distance, lookalike?) for the nearest reference, or None."""
    skeleton = _skeleton(name, ecosystem)
    best = None
    for reference in references:
        ref_skeleton = _skeleton(reference, ecosystem)
        if skeleton == ref_skeleton:
            lookalike, d = True, distance(_normalize(name, ecosystem), _normalize(reference, ecosystem))
        elif len(ref_skeleton) >= MIN_NAME:
            lookalike, d = False, distance(skeleton, ref_skeleton)
            if d > _max_distance(ref_skeleton):
                continue
        else:
            continue
        key = (not lookalike, d, reference)  # lookalikes first, then nearest
        if best is None or key < best[0]:
            best = (key, reference, d, lookalike)
    return None if best is None else best[1:]


def _match(name: str, ecosystem: str) -> tuple[str, str, str, int] | None:
    """(rule_id, imitated name, how, distance) or None."""
    popular = POPULAR_PACKAGES[ecosystem]
    normalized = _normalize(name, ecosystem)
    if normalized in {_normalize(p, ecosystem) for p in popular}:
        return None  # it IS the popular package

    scoped = re.match(r"^@([^/]+)/(.+)$", normalized) if ecosystem == "npm" else None
    if scoped:
        scope = scoped.group(1)
        if scope in KNOWN_SCOPES or len(scope) < MIN_NAME:
            return None
        hit = _closest(scope, [s for s in KNOWN_SCOPES if len(s) >= MIN_NAME], ecosystem)
        if hit is None:
            return None
        reference, d, lookalike = hit
        how = "lookalike characters" if lookalike else f"edit distance {d}"
        return "TYPO003", f"@{reference}", how, d

    if len(normalized) < MIN_NAME:
        return None
    hit = _closest(name, [p for p in popular if not p.startswith("@")], ecosystem)
    if hit is None:
        return None
    reference, d, lookalike = hit
    if lookalike:
        return "TYPO002", reference, "lookalike characters", d
    return "TYPO001", reference, f"edit distance {d}", d


def check(_pkg_dir: Path, meta: dict) -> list[Finding]:
    """Find a package name imitating a popular package in its ecosystem.

    ``meta`` must identify the requested package with ``name`` or
    ``package_name`` and its ecosystem (``npm`` or ``pypi``). Registry fields
    (``downloads``, ``created`` / ``published``) drive the popularity guard.
    """
    candidate = _candidate(meta)
    if candidate is None or is_popular(meta):
        return []
    ecosystem, original_name = candidate
    match = _match(original_name, ecosystem)
    if match is None:
        return []

    rule_id, reference, how, d = match
    if rule_id == "TYPO003":
        claim = f"uses a scope imitating the well-known npm scope `{reference}` ({how})"
    elif rule_id == "TYPO002":
        claim = f"uses characters confusable with popular {ecosystem} package `{reference}`"
    else:
        claim = f"is {d} edit{'s' if d != 1 else ''} away from popular {ecosystem} package `{reference}`"

    weak = weak_signals(meta)
    if weak:
        return [Finding(
            "typosquat", "suspicious", 25,
            f"Package name `{original_name}` {claim}; confirmed by {', '.join(weak)}",
            rule_id=rule_id, category="typosquatting",
            confidence=0.9 if len(weak) > 1 else 0.8,
        )]
    why = ("no registry data to check its popularity" if not has_registry_data(meta)
           else "registry data shows an established package")
    return [Finding(
        "typosquat", "info", 0,
        f"Package name `{original_name}` {claim} (unconfirmed: {why}; similarity alone is not enough)",
        rule_id=rule_id, category="typosquatting", confidence=0.3,
    )]
