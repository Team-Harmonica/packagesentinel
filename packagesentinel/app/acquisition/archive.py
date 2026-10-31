"""Safe archive validation and extraction (stdlib only). Used by upload, npm and PyPI.

Nothing in an archive is ever executed. Entries are never handed to
``tarfile.extract``/``zipfile.extract``; each regular file is copied out by
hand into a path that has been checked to stay inside the extraction root.

Guarantees:
  * format check by magic bytes; corrupt / truncated / unknown archives raise
    ArchiveValidationError
  * path traversal (zip-slip / tar-slip): absolute paths, drive letters, ``..``
    components, and anything whose ``os.path.realpath`` escapes the root ->
    the whole archive is REJECTED (ExtractionError)
  * zip / gzip bombs: total uncompressed bytes, entry count and the zip
    compression ratio are capped -> REJECTED. Decompression is streamed through
    a byte counter, so a lying size header cannot get past the cap.
  * per-file cap: oversized single files are SKIPPED and reported
  * symlinks, hard links, devices and FIFOs are SKIPPED and reported
  * extracted files are written 0644 (never executable), owner/mtime not preserved
  * SHA-256 of the exact input bytes (same bytes -> same digest)
"""

from __future__ import annotations

import email.parser
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.acquisition.errors import ArchiveValidationError, ExtractionError


@dataclass(frozen=True)
class Limits:
    max_archive_bytes: int = 50 * 1024 * 1024        # compressed input
    max_total_bytes: int = 250 * 1024 * 1024         # all extracted files together
    max_file_bytes: int = 20 * 1024 * 1024           # one file (matches the scanner's cap)
    max_members: int = 20_000
    max_zip_ratio: int = 200                         # uncompressed / compressed, per entry
    zip_ratio_min_bytes: int = 1024 * 1024           # tiny files compress absurdly; ignore them


DEFAULT_LIMITS = Limits()
CHUNK = 1024 * 1024


@dataclass
class ExtractedArchive:
    root: Path               # where entries were written
    pkg_dir: Path            # the package directory inside root (npm "package/", sdist "name-ver/")
    sha256: str
    archive_format: str      # "tar.gz" | "tar" | "zip"
    files: int = 0
    total_bytes: int = 0
    warnings: list[str] = field(default_factory=list)
    skipped_files: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_format(data: bytes) -> str:
    if data[:2] == b"\x1f\x8b":
        return "tar.gz"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    raise ArchiveValidationError("not a supported archive (expected .tgz / .tar.gz / .tar / .zip / .whl)")


# --- path safety --------------------------------------------------------------

_DRIVE = re.compile(r"^[A-Za-z]:")


def safe_relpath(name: str) -> PurePosixPath:
    """Validate an archive entry name; return it as a relative POSIX path.

    Raises ExtractionError for anything that could land outside the root."""
    if "\x00" in name:
        raise ExtractionError(f"unsafe entry name (NUL byte): {name!r}")
    unified = name.replace("\\", "/")  # Windows-made zips use backslashes
    if unified.startswith("/") or _DRIVE.match(unified):
        raise ExtractionError(f"unsafe absolute path in archive: {name!r}")
    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ExtractionError(f"path traversal in archive entry: {name!r}")
    if not parts:
        raise ExtractionError(f"empty entry name: {name!r}")
    return PurePosixPath(*parts)


def _target(root: Path, rel: PurePosixPath) -> Path:
    real_root = os.path.realpath(root)
    target = os.path.realpath(os.path.join(real_root, *rel.parts))
    if os.path.commonpath([real_root, target]) != real_root:
        raise ExtractionError(f"entry escapes extraction root: {rel}")
    return Path(target)


# --- streaming helpers ------------------------------------------------------------


class _CountingReader(io.RawIOBase):
    """Wraps a decompressing stream and refuses to yield more than ``limit`` bytes."""

    def __init__(self, raw, limit: int):
        self.raw, self.limit, self.count = raw, limit, 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self.raw.read(len(b))
        self.count += len(data)
        if self.count > self.limit:
            raise ExtractionError(f"archive decompresses to more than {self.limit} bytes (decompression bomb)")
        b[: len(data)] = data
        return len(data)


class _Writer:
    def __init__(self, result: ExtractedArchive, root: Path, limits: Limits):
        self.result, self.root, self.limits = result, root, limits
        self.members = 0

    def count_member(self) -> None:
        self.members += 1
        if self.members > self.limits.max_members:
            raise ExtractionError(f"archive has more than {self.limits.max_members} entries")

    def skip(self, path: str, reason: str) -> None:
        self.result.skipped_files.append((path, reason))
        self.result.warnings.append(f"skipped {path}: {reason}")

    def directory(self, rel: PurePosixPath) -> None:
        _target(self.root, rel).mkdir(parents=True, exist_ok=True)

    def file(self, rel: PurePosixPath, declared_size: int, stream) -> None:
        if declared_size > self.limits.max_file_bytes:
            self.skip(str(rel), f"file too large ({declared_size} bytes > {self.limits.max_file_bytes})")
            return
        target = _target(self.root, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_dir():
            raise ExtractionError(f"entry collides with a directory: {rel}")
        written = 0
        with open(target, "wb") as out:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > self.limits.max_file_bytes:  # header lied about the size
                    out.close()
                    target.unlink()
                    self.skip(str(rel), f"file too large (> {self.limits.max_file_bytes} bytes)")
                    return
                if self.result.total_bytes + written > self.limits.max_total_bytes:
                    raise ExtractionError(f"archive expands to more than {self.limits.max_total_bytes} bytes "
                                          "(decompression bomb)")
                out.write(chunk)
        os.chmod(target, 0o644)
        self.result.files += 1
        self.result.total_bytes += written


# --- format-specific extraction -------------------------------------------------------


def _extract_tar(data: bytes, gz: bool, w: _Writer) -> None:
    raw = gzip.GzipFile(fileobj=io.BytesIO(data)) if gz else io.BytesIO(data)
    stream = io.BufferedReader(_CountingReader(raw, w.limits.max_total_bytes + 64 * 1024 * 1024))
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tf:  # streaming: one pass, bounded
            for member in tf:
                w.count_member()
                rel = safe_relpath(member.name)
                if member.isdir():
                    w.directory(rel)
                elif member.isreg():
                    w.file(rel, member.size, tf.extractfile(member))
                elif member.issym() or member.islnk():
                    w.skip(str(rel), f"link to {member.linkname!r} not extracted")
                else:
                    w.skip(str(rel), "device / FIFO / special file not extracted")
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise ArchiveValidationError(f"corrupt or truncated tar archive: {exc}") from exc


def _extract_zip(data: bytes, w: _Writer) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ArchiveValidationError(f"corrupt zip archive: {exc}") from exc
    if len(infos) > w.limits.max_members:
        raise ExtractionError(f"archive has more than {w.limits.max_members} entries")
    if sum(i.file_size for i in infos) > w.limits.max_total_bytes:
        raise ExtractionError(f"archive declares more than {w.limits.max_total_bytes} uncompressed bytes "
                              "(decompression bomb)")
    for info in infos:  # validate every name before writing anything
        safe_relpath(info.filename)
        if (info.file_size >= w.limits.zip_ratio_min_bytes and info.compress_size
                and info.file_size / info.compress_size > w.limits.max_zip_ratio):
            raise ExtractionError(f"entry {info.filename!r} compresses {info.file_size // info.compress_size}:1 "
                                  "(zip bomb)")
    try:
        for info in infos:
            w.count_member()
            rel = safe_relpath(info.filename)
            # many zip writers store only permission bits (no file-type bits): that's a plain file
            ftype = stat.S_IFMT(info.external_attr >> 16)
            if info.is_dir():
                w.directory(rel)
            elif ftype == stat.S_IFLNK:
                w.skip(str(rel), "symlink not extracted")
            elif ftype and ftype != stat.S_IFREG:
                w.skip(str(rel), "special file not extracted")
            else:
                with zf.open(info) as src:
                    w.file(rel, info.file_size, src)
    except (zipfile.BadZipFile, EOFError, zlib.error) as exc:
        raise ArchiveValidationError(f"corrupt zip archive: {exc}") from exc
    except NotImplementedError as exc:  # unsupported compression / encryption
        raise ArchiveValidationError(f"unsupported zip entry: {exc}") from exc
    except RuntimeError as exc:  # encrypted entries
        raise ArchiveValidationError(f"unreadable zip entry: {exc}") from exc


def _package_dir(root: Path) -> Path:
    """npm tarballs wrap everything in package/, sdists in name-version/: use that."""
    entries = [p for p in root.iterdir()]
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return root


def extract_archive(data: bytes, dest: str | Path, limits: Limits = DEFAULT_LIMITS) -> ExtractedArchive:
    """Validate and extract ``data`` into the (empty or new) directory ``dest``."""
    if len(data) > limits.max_archive_bytes:
        raise ArchiveValidationError(f"archive is {len(data)} bytes; limit is {limits.max_archive_bytes}")
    fmt = detect_format(data)
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    result = ExtractedArchive(root=root, pkg_dir=root, sha256=sha256_bytes(data), archive_format=fmt)
    writer = _Writer(result, root, limits)
    try:
        if fmt == "zip":
            _extract_zip(data, writer)
        else:
            _extract_tar(data, fmt == "tar.gz", writer)
    except Exception:
        _empty_dir(root)  # never leave a half-extracted malicious tree behind
        raise
    if result.files == 0:
        raise ArchiveValidationError("archive contains no extractable files")
    result.pkg_dir = _package_dir(root)
    return result


def _empty_dir(root: Path) -> None:
    for child in root.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


# --- metadata -------------------------------------------------------------------------


def empty_meta(name: str = "", ecosystem: str = "") -> dict:
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": "",
        "published": None,
        "downloads": None,
        "maintainers": [],
        "repo_url": None,
        "dependencies": {},
    }


def _person(p) -> str | None:
    if isinstance(p, dict):
        return p.get("name") or p.get("email")
    if isinstance(p, str):
        return re.sub(r"\s*[<(].*$", "", p).strip() or None
    return None


def _clean_url(url) -> str | None:
    if isinstance(url, dict):
        url = url.get("url")
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip()
    url = re.sub(r"^git\+", "", url)
    url = re.sub(r"^git://", "https://", url)
    url = re.sub(r"^github:", "https://github.com/", url)
    return re.sub(r"\.git$", "", url)


def npm_meta(pkg_dir: Path) -> dict | None:
    manifest = pkg_dir / "package.json"
    if not manifest.is_file() or manifest.is_symlink():
        return None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))  # data only, never executed
    except (ValueError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    meta = empty_meta(str(data.get("name") or ""), "npm")
    meta["version"] = str(data.get("version") or "")
    deps = data.get("dependencies")
    meta["dependencies"] = {str(k): str(v) for k, v in deps.items()} if isinstance(deps, dict) else {}
    people = (data.get("maintainers") or []) + ([data["author"]] if data.get("author") else [])
    meta["maintainers"] = [n for n in (_person(p) for p in people) if n]
    meta["repo_url"] = _clean_url(data.get("repository")) or _clean_url(data.get("homepage"))
    for key in ("description", "keywords"):  # read by scoring's purpose dampener
        if data.get(key):
            meta[key] = data[key]
    return meta


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")
_REPO_LABELS = ("source", "repository", "code", "github", "homepage", "home")


def pypi_core_meta(text: str) -> dict:
    """Parse PKG-INFO / METADATA (RFC 822 style) into the shared meta shape."""
    msg = email.parser.Parser().parsestr(text, headersonly=True)
    meta = empty_meta(msg.get("Name", "") or "", "pypi")
    meta["version"] = msg.get("Version", "") or ""
    deps: dict[str, str] = {}
    for req in msg.get_all("Requires-Dist") or []:
        m = _REQ_NAME.match(req)
        if m:
            deps[m.group(1)] = m.group(2).strip()
    meta["dependencies"] = deps
    people = [msg.get("Maintainer"), msg.get("Author"), msg.get("Maintainer-email"), msg.get("Author-email")]
    meta["maintainers"] = list(dict.fromkeys(n for n in (_person(p) for p in people if p) if n))
    urls = {}
    for entry in msg.get_all("Project-URL") or []:
        label, _, url = entry.partition(",")
        urls[label.strip().lower()] = url.strip()
    for label in _REPO_LABELS:
        hit = next((u for k, u in urls.items() if label in k), None)
        if hit:
            meta["repo_url"] = _clean_url(hit)
            break
    else:
        meta["repo_url"] = _clean_url(msg.get("Home-page"))
    if msg.get("Summary"):
        meta["description"] = msg.get("Summary")
    if msg.get("Keywords"):
        meta["keywords"] = [k for k in re.split(r"[,\s]+", msg.get("Keywords")) if k]
    return meta


def pypi_meta(pkg_dir: Path, root: Path | None = None) -> dict | None:
    candidates = [pkg_dir / "PKG-INFO"]
    for base in {pkg_dir, root or pkg_dir}:
        candidates += sorted(base.glob("*.dist-info/METADATA")) + sorted(base.glob("*.egg-info/PKG-INFO"))
    for path in candidates:
        if path.is_file() and not path.is_symlink():
            try:
                return pypi_core_meta(path.read_text(encoding="utf-8", errors="replace"))
            except Exception:  # malformed metadata: fall through to the next candidate
                continue
    return None


def read_metadata(pkg_dir: Path, root: Path | None = None, ecosystem: str | None = None) -> dict:
    """Normalized meta for an extracted (or local) package directory."""
    order = (pypi_meta, npm_meta) if ecosystem == "pypi" else (npm_meta, pypi_meta)
    for reader in order:
        meta = reader(pkg_dir, root) if reader is pypi_meta else reader(pkg_dir)
        if meta:
            if not meta["name"]:
                meta["name"] = pkg_dir.name
            return meta
    return empty_meta(pkg_dir.name, ecosystem or "")


# --- upload entry point -------------------------------------------------------------------


def extract_with_meta(data: bytes, dest: str | Path | None, ecosystem: str | None, source: str,
                      limits: Limits = DEFAULT_LIMITS) -> tuple[Path, dict]:
    """Shared tail of upload / npm / PyPI acquisition: extract + metadata + report."""
    owned = dest is None
    root = Path(tempfile.mkdtemp(prefix="pkgsentinel-")) if owned else Path(dest)
    try:
        result = extract_archive(data, root, limits)
    except Exception:
        if owned:
            shutil.rmtree(root, ignore_errors=True)
        raise
    meta = read_metadata(result.pkg_dir, result.root, ecosystem)
    meta["acquisition"] = {
        "source": source,
        "archive_sha256": result.sha256,
        "archive_format": result.archive_format,
        "files": result.files,
        "total_bytes": result.total_bytes,
        "warnings": result.warnings,
        "skipped_files": [{"path": p, "reason": r} for p, r in result.skipped_files],
        "temp_root": str(root) if owned else None,
    }
    return result.pkg_dir, meta


def extract_upload(file_bytes: bytes, dest: str | Path | None = None, ecosystem: str | None = None,
                   limits: Limits = DEFAULT_LIMITS) -> tuple[Path, dict]:
    """Uploaded archive bytes -> (pkg_dir, meta), the shape run_scanner consumes.

    ``dest``: directory to extract into (the caller owns and cleans it, e.g. a
    TemporaryDirectory in the web server). If omitted, a new temp directory is
    created; its path is in meta["acquisition"]["temp_root"] for cleanup().
    meta["acquisition"] carries the SHA-256, format, warnings and skipped files.
    """
    return extract_with_meta(file_bytes, dest, ecosystem, "upload", limits)


def cleanup(meta: dict) -> None:
    """Remove a temp directory created by extract_upload/resolve (no-op otherwise)."""
    root = (meta.get("acquisition") or {}).get("temp_root")
    if root and Path(root).name.startswith("pkgsentinel-"):
        shutil.rmtree(root, ignore_errors=True)
