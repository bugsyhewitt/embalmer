"""Binary analysis handoff to blight.

embalmer does not analyze binaries itself. It locates ELF binaries in the
extracted firmware tree and hands each off to `blight` (the suite's
pattern-based CWE detector — fast and broad), then aggregates blight's JSON
output into the unified embalmer report.

[Worker decision: blight JSON contract]
At the time this was written the blight repo contained only a LICENSE, so the
exact CLI surface was not yet fixed. We assume the conventional suite contract:

    blight --json <path-to-binary>   ->   stdout JSON

We parse blight's stdout as JSON and accept either of two shapes:
  1. {"findings": [ {...}, ... ]}
  2. a bare list [ {...}, ... ]
Each blight finding is normalized into an embalmer `Finding(category="binary")`.
If blight emits a shape we don't recognize, we attach the raw payload under
`extra["raw"]` so nothing is silently dropped. The subprocess boundary is
mocked in unit tests; a real-binary integration test is marked
`@pytest.mark.integration`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import Finding

# ELF magic — used to identify candidate binaries cheaply without depending on
# python-magic for this hot path (python-magic is still a declared dependency
# and used for richer file typing elsewhere if needed).
_ELF_MAGIC = b"\x7fELF"


class BlightError(RuntimeError):
    """Raised when the blight binary cannot be located or run."""


def find_binaries(extract_root: str | Path) -> list[Path]:
    """Return ELF binaries found anywhere under `extract_root`."""
    root = Path(extract_root)
    binaries: list[Path] = []
    if not root.exists():
        return binaries
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as fh:
                if fh.read(4) == _ELF_MAGIC:
                    binaries.append(path)
        except OSError:
            continue
    return binaries


def _run_blight(blight_binary: str, target: Path) -> Any:
    """Invoke blight on a single binary and return parsed JSON.

    Isolated for monkeypatching in unit tests.
    """
    cmd = [blight_binary, "--json", str(target)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise BlightError(
            f"blight exited {proc.returncode} on {target}: {proc.stderr.strip()}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise BlightError(f"blight emitted non-JSON output on {target}: {exc}") from exc


def _normalize(payload: Any, rel_path: str) -> list[Finding]:
    """Convert blight's JSON payload into embalmer Findings."""
    if isinstance(payload, dict) and "findings" in payload:
        raw_items = payload["findings"]
    elif isinstance(payload, list):
        raw_items = payload
    else:
        # Unknown shape — preserve it rather than drop it.
        return [
            Finding(
                category="binary",
                path=rel_path,
                type="blight_raw",
                detail="unrecognized blight output shape",
                severity="info",
                extra={"raw": payload},
            )
        ]

    findings: list[Finding] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        cwe = item.get("cwe") or item.get("id") or "unknown"
        findings.append(
            Finding(
                category="binary",
                path=rel_path,
                type=str(cwe),
                detail=str(item.get("message") or item.get("detail") or ""),
                severity=str(item.get("severity", "info")),
                extra={k: v for k, v in item.items()
                       if k not in {"cwe", "id", "message", "detail", "severity"}},
            )
        )
    return findings


def analyze(extract_root: str | Path, blight_binary: str = "blight") -> list[Finding]:
    """Locate binaries under `extract_root` and aggregate blight findings.

    Raises BlightError if the blight binary is not on PATH and binaries were
    found to analyze (no binaries -> no error, just an empty list).
    """
    root = Path(extract_root)
    binaries = find_binaries(root)
    if not binaries:
        return []

    if shutil.which(blight_binary) is None and not Path(blight_binary).is_file():
        raise BlightError(
            f"blight binary {blight_binary!r} not found. Pass --blight-binary "
            "with the path to a blight executable."
        )

    findings: list[Finding] = []
    for binary in binaries:
        rel = str(binary.relative_to(root)) if root in binary.parents or binary.parent == root else str(binary)
        payload = _run_blight(blight_binary, binary)
        findings.extend(_normalize(payload, rel))
    return findings
