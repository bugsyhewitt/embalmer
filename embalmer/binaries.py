"""Binary analysis handoff via binary-pipeline.

embalmer does not analyze binaries itself. It locates ELF binaries in the
extracted firmware tree using ``binary_pipeline.find_binaries`` and hands each
off to ``blight`` (the suite's pattern-based CWE detector) via
``binary_pipeline.SubprocessAnalyzer``, then normalizes the
``BinaryFinding`` objects from the schema into embalmer's own ``Finding`` type
so they appear correctly in the unified report.

[Worker decision: SubprocessAnalyzer over direct Python import]
embalmer uses SubprocessAnalyzer to call the blight CLI rather than importing
blight as a Python library. This preserves the existing architecture (blight as
an external tool, not a hard dependency) while still going through the shared
binary-pipeline interface. The ``_analyzer`` parameter in ``analyze()`` lets
tests inject a mock callable instead of patching the subprocess layer.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from binary_finding_schema import BinaryFinding
from binary_pipeline import find_binaries, run_pipeline, SubprocessAnalyzer  # noqa: F401 — re-exported
from binary_pipeline._subprocess import SubprocessAnalyzerError

from .models import Finding


class BlightError(RuntimeError):
    """Raised when the blight binary cannot be located or run."""


def _make_blight_analyzer(blight_binary: str) -> SubprocessAnalyzer:
    """Build a SubprocessAnalyzer that invokes ``blight --json <binary>``."""
    if shutil.which(blight_binary) is None and not Path(blight_binary).is_file():
        raise BlightError(
            f"blight binary {blight_binary!r} not found. Pass --blight-binary "
            "with the path to a blight executable."
        )
    return SubprocessAnalyzer(blight_binary, extra_args=["--json"])


def _to_embalmer_finding(bf: BinaryFinding, rel_path: str) -> Finding:
    """Convert a BinaryFinding from the schema into an embalmer Finding."""
    # Extract the numeric CWE from "CWE-N" for the type field.
    cwe_str = bf.cwe_id  # e.g. "CWE-120"
    return Finding(
        category="binary",
        path=rel_path,
        type=cwe_str,
        detail=bf.evidence,
        severity="info",
        extra={k: v for k, v in {
            "function": bf.function,
            "address": bf.address,
            "symbol": bf.symbol,
        }.items() if v is not None},
    )


def analyze(
    extract_root: str | Path,
    blight_binary: str = "blight",
    _analyzer: Any = None,
) -> list[Finding]:
    """Locate ELF binaries under ``extract_root`` and aggregate blight findings.

    Uses :func:`~binary_pipeline.find_binaries` for ELF discovery and
    :class:`~binary_pipeline.SubprocessAnalyzer` (or a test-injected callable)
    for the per-binary analysis.

    Args:
        extract_root: Directory containing the extracted firmware tree.
        blight_binary: Path or name of the blight CLI (default: ``"blight"``).
        _analyzer: Optional override for the analyzer callable. Used by unit
            tests to inject a mock without touching subprocess.

    Returns:
        Flat list of embalmer :class:`~embalmer.models.Finding` objects with
        ``category="binary"``.

    Raises:
        BlightError: If blight is not on PATH and binaries were found.
    """
    root = Path(extract_root)
    binaries = find_binaries(root)
    if not binaries:
        return []

    if _analyzer is None:
        analyzer = _make_blight_analyzer(blight_binary)
    else:
        analyzer = _analyzer

    findings: list[Finding] = []
    for binary in binaries:
        # Compute a root-relative path for the finding record.
        try:
            rel = str(binary.relative_to(root))
        except ValueError:
            rel = str(binary)

        try:
            binary_findings = run_pipeline([binary], [analyzer])
        except SubprocessAnalyzerError as exc:
            raise BlightError(str(exc)) from exc

        for bf in binary_findings:
            findings.append(_to_embalmer_finding(bf, rel))

    return findings
