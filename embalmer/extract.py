"""Extraction backend: orchestrate unblob, with an optional binwalk fallback.

embalmer does not reimplement extraction. It shells out to an external
extractor CLI (the stable, documented interface) to recursively extract a
firmware image into a working directory, then walks the result to build a
structured tree.

[Worker decision: unblob CLI over Python API]
We invoke `unblob -e <workdir> <firmware>` via subprocess rather than the
`unblob.processing` Python API. The CLI is the stable contract across unblob
versions; the Python API (ExtractionConfig/process_file) requires constructing
handler registries and shifts shape between releases. This also matches the
suite convention of shelling out to heavy external tools (miasma -> nmap,
blight -> radare2). The subprocess boundary is mocked in unit tests so the
suite runs without unblob installed; a real integration test exercises the
live binary.

[Worker decision (R8): binwalk fallback backend, unblob primary]
unblob extracts more formats and runs faster, so it stays the default primary.
But unblob silently skips formats it does not recognize; binwalk's heuristic
signature scanning catches some proprietary/corrupted images unblob misses.
We add a second backend (binwalk v3, ReFirmLabs Rust rewrite) and an
``extractor`` selector: ``"unblob"`` (primary only), ``"binwalk"`` (binwalk
only), or ``"auto"`` (default — try unblob, and if it errors out or produces
zero files, retry with binwalk into a clean workdir). The two backends share
the same ``_build_tree`` walk and emit the identical ``ExtractionResult`` shape
so every downstream check runs unchanged regardless of which backend produced
the tree. ``ExtractionResult.extractor_used`` records which one actually won so
the fallback is visible in the report.
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
BINWALK_BINARY = "binwalk"

VALID_EXTRACTORS = ("unblob", "binwalk", "auto")


class ExtractionError(RuntimeError):
    """Raised when the selected extractor is unavailable or extraction fails."""


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


def _run_binwalk(firmware: Path, workdir: Path) -> None:
    """Invoke the binwalk v3 (Rust) CLI to extract `firmware` into `workdir`.

    binwalk v3 takes ``-e`` to extract and ``--directory <dir>`` to choose the
    output root, mirroring unblob's flag surface closely enough that downstream
    checks see an identical tree. Isolated as its own seam for the same testing
    reasons as ``_run_unblob``.
    """
    if shutil.which(BINWALK_BINARY) is None:
        raise ExtractionError(
            f"binwalk binary {BINWALK_BINARY!r} not found on PATH. "
            "Install binwalk v3 (Rust) — see the README section "
            "'System dependencies for unblob'."
        )

    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [BINWALK_BINARY, "-e", "--directory", str(workdir), str(firmware)]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and not _has_extracted_files(workdir):
        raise ExtractionError(
            f"binwalk exited {proc.returncode} and produced no output.\n"
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


def _clear_workdir(workdir: Path) -> None:
    """Empty `workdir` between backend attempts without removing the dir itself.

    The auto fallback re-extracts into the same workdir; a partial unblob run
    that produced no usable files might still have left empty scaffolding, so
    we wipe it before handing the directory to binwalk to keep the resulting
    tree clean.
    """
    if not workdir.exists():
        return
    for entry in workdir.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            try:
                entry.unlink()
            except OSError:
                pass


def extract(
    firmware: str | Path,
    workdir: str | Path,
    extractor: str = "auto",
) -> ExtractionResult:
    """Extract `firmware` into `workdir` and return a structured result.

    Args:
        firmware: Path to the firmware image.
        workdir: Directory to extract into.
        extractor: Which backend to use — ``"unblob"`` (primary only),
            ``"binwalk"`` (binwalk only), or ``"auto"`` (default: try unblob,
            fall back to binwalk if unblob errors out or yields zero files).

    Raises ExtractionError if the input does not exist, the requested backend
    is unavailable, or extraction yields nothing usable. In ``auto`` mode the
    error from the fallback (binwalk) is surfaced when both backends fail.
    """
    firmware = Path(firmware)
    workdir = Path(workdir)

    if extractor not in VALID_EXTRACTORS:
        raise ExtractionError(
            f"unknown extractor {extractor!r}; choose one of {VALID_EXTRACTORS}"
        )

    if not firmware.is_file():
        raise ExtractionError(f"firmware image not found: {firmware}")

    start = time.monotonic()
    used = _dispatch(firmware, workdir, extractor)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    tree, file_count = _build_tree(workdir)

    return ExtractionResult(
        extraction_tree=tree,
        file_count=file_count,
        extraction_time_ms=elapsed_ms,
        extract_root=str(workdir),
        extractor_used=used,
    )


def _dispatch(firmware: Path, workdir: Path, extractor: str) -> str:
    """Run the selected backend(s) and return the name of the one that won.

    For ``auto``: unblob runs first; if it raises ExtractionError OR completes
    but leaves an empty workdir, the workdir is cleared and binwalk is tried.
    """
    if extractor == "unblob":
        _run_unblob(firmware, workdir)
        return "unblob"

    if extractor == "binwalk":
        _run_binwalk(firmware, workdir)
        return "binwalk"

    # auto: unblob primary, binwalk fallback.
    unblob_failed = False
    try:
        _run_unblob(firmware, workdir)
    except ExtractionError:
        unblob_failed = True

    if not unblob_failed and _has_extracted_files(workdir):
        return "unblob"

    # unblob errored out or produced zero files — fall back to binwalk into a
    # clean workdir so the tree reflects only binwalk's output.
    _clear_workdir(workdir)
    _run_binwalk(firmware, workdir)
    return "binwalk"
