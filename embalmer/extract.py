"""Extraction backend: orchestrate unblob.

embalmer does not reimplement extraction. It shells out to the `unblob` CLI
(the stable, documented interface) to recursively extract a firmware image
into a working directory, then walks the result to build a structured tree.

[Worker decision: unblob CLI over Python API]
We invoke `unblob -e <workdir> <firmware>` via subprocess rather than the
`unblob.processing` Python API. The CLI is the stable contract across unblob
versions; the Python API (ExtractionConfig/process_file) requires constructing
handler registries and shifts shape between releases. This also matches the
suite convention of shelling out to heavy external tools (miasma -> nmap,
blight -> radare2). The subprocess boundary is mocked in unit tests so the
suite runs without unblob installed; a real integration test exercises the
live binary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .models import ExtractionResult

UNBLOB_BINARY = "unblob"


class ExtractionError(RuntimeError):
    """Raised when unblob is unavailable or extraction fails outright."""


def _run_unblob(firmware: Path, workdir: Path) -> None:
    """Invoke the unblob CLI to extract `firmware` into `workdir`.

    Isolated into its own function so unit tests can monkeypatch this single
    seam instead of patching subprocess globally.
    """
    if shutil.which(UNBLOB_BINARY) is None:
        raise ExtractionError(
            f"unblob binary {UNBLOB_BINARY!r} not found on PATH. "
            "See the README section 'System dependencies for unblob'."
        )

    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [UNBLOB_BINARY, "--extract-dir", str(workdir), str(firmware)]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    # unblob exits non-zero on hard failures; partial-extraction warnings
    # (e.g. a single missing extractor for one chunk type) still produce a
    # usable tree, so we only treat a completely empty workdir as fatal.
    if proc.returncode != 0 and not _has_extracted_files(workdir):
        raise ExtractionError(
            f"unblob exited {proc.returncode} and produced no output.\n"
            f"stderr: {proc.stderr.strip()}"
        )


def _has_extracted_files(workdir: Path) -> bool:
    for _root, _dirs, files in os.walk(workdir):
        if files:
            return True
    return False


def _build_tree(root: Path) -> tuple[dict[str, Any], int]:
    """Walk `root` and build a nested dict tree plus a file count.

    Directories map to nested dicts; files map to their size in bytes. The
    file count excludes directories.
    """
    file_count = 0

    def walk(path: Path) -> dict[str, Any]:
        nonlocal file_count
        node: dict[str, Any] = {}
        try:
            entries = sorted(path.iterdir(), key=lambda p: p.name)
        except OSError:
            return node
        for entry in entries:
            if entry.is_symlink():
                node[entry.name] = {"_type": "symlink", "target": os.readlink(entry)}
            elif entry.is_dir():
                node[entry.name] = walk(entry)
            else:
                file_count += 1
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = 0
                node[entry.name] = {"_type": "file", "size": size}
        return node

    tree = walk(root)
    return tree, file_count


def extract(firmware: str | Path, workdir: str | Path) -> ExtractionResult:
    """Extract `firmware` into `workdir` and return a structured result.

    Raises ExtractionError if the input does not exist or extraction yields
    nothing usable.
    """
    firmware = Path(firmware)
    workdir = Path(workdir)

    if not firmware.is_file():
        raise ExtractionError(f"firmware image not found: {firmware}")

    start = time.monotonic()
    _run_unblob(firmware, workdir)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    tree, file_count = _build_tree(workdir)

    return ExtractionResult(
        extraction_tree=tree,
        file_count=file_count,
        extraction_time_ms=elapsed_ms,
        extract_root=str(workdir),
    )
