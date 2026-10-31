"""Adapter from the stdlib fetchers to the async PackageAcquirer contract (Issue #1).

pydantic (via contracts.py) is imported only here, inside acquire(), so the
fetchers themselves stay importable by the zero-dependency scanner.
"""

from __future__ import annotations

import asyncio
from tempfile import TemporaryDirectory
from typing import Callable


async def acquire_with(fetcher: Callable, request, ecosystem: str):
    from app.acquisition.contracts import AcquiredPackage, SkippedFile

    tmp = TemporaryDirectory(prefix="pkgsentinel-")
    try:
        pkg_dir, meta = await asyncio.to_thread(fetcher, request.name, request.version, tmp.name)
        report = meta.pop("acquisition")
        return AcquiredPackage(
            package_name=meta.get("name") or request.name,
            ecosystem=ecosystem,
            version=meta.get("version") or request.version,
            extracted_dir=pkg_dir,
            archive_sha256=report["archive_sha256"],
            metadata=meta,
            warnings=report["warnings"],
            skipped_files=[SkippedFile(**s) for s in report["skipped_files"]],
            temporary_directory=tmp,
        )
    except BaseException:
        tmp.cleanup()
        raise
