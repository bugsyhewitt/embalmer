"""Binary analysis handoff via binary-pipeline.

embalmer does not analyze binaries itself. It locates ELF binaries in the
extracted firmware tree using ``binary_pipeline.find_binaries`` and hands each
off to one or more external analyzers via ``binary_pipeline.SubprocessAnalyzer``,
then normalizes the ``BinaryFinding`` objects from the schema into embalmer's
own ``Finding`` type so they appear correctly in the unified report.

Two analyzers are supported:

* ``blight`` — the suite's fast, radare2-backed pattern matcher. The default,
  invoked as ``blight --json <binary>``.
* ``autopsy`` — the suite's angr-backed symbolic-execution engine for deeper,
  flow-sensitive CWE analysis. Invoked as
  ``autopsy --format json --binary <binary>``.

``--analyzer both`` runs both over every ELF and aggregates the findings.

[Worker decision: SubprocessAnalyzer over direct Python import]
embalmer uses SubprocessAnalyzer to call the analyzer CLIs rather than importing
them as Python libraries. This preserves the existing architecture (analyzers as
external tools, not hard dependencies — autopsy in particular pulls in angr,
which must not become an embalmer dependency) while still going through the
shared binary-pipeline interface. The ``_analyzer`` parameter in ``analyze()``
lets tests inject a mock callable instead of patching the subprocess layer.

[Worker decision: reuse SubprocessAnalyzer for autopsy unchanged]
autopsy's JSON output shape (``{"findings": [{"cwe": <int>, "function": ...,
"address": "0x..", "evidence": ...}, ...]}``) is already fully consumable by
``binary_pipeline.SubprocessAnalyzer._item_to_finding``, which normalizes both
the ``cwe``/``cwe_id`` keys and the address form. No bespoke parser is needed;
autopsy differs from blight only in its CLI flags, so the autopsy analyzer is a
``SubprocessAnalyzer`` configured with ``extra_args=["--format", "json",
"--binary"]`` (the binary path is appended last, satisfying autopsy's
``--binary PATH`` flag).

[Worker decision: ThreadPoolExecutor, not ProcessPoolExecutor]
POST_V01 Rank 9 suggests ``ProcessPoolExecutor``. The real per-binary work is
each analyzer's *subprocess* invocation (``blight`` / ``autopsy`` are external
CLIs), so the in-process work is purely subprocess spawn + wait + JSON parse —
I/O-bound, and the GIL is released while the child process runs. A
``ThreadPoolExecutor`` therefore achieves the same wall-clock parallelism with
none of the process-pool downsides: the analyzer callables (and the test mocks
injected via ``_analyzer``/``_analyzers``) are ordinary closures that are not
picklable and so could not cross a process boundary. Per-binary results are
re-assembled in the original ``find_binaries`` order so output stays
deterministic regardless of completion order or ``jobs`` count.
"""

from __future__ import annotations

import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from binary_finding_schema import BinaryFinding
from binary_pipeline import find_binaries, run_pipeline, SubprocessAnalyzer  # noqa: F401 — re-exported
from binary_pipeline._subprocess import SubprocessAnalyzerError

from .models import Finding


#: The analyzer selectors accepted by ``analyze`` and the CLI ``--analyzer`` flag.
VALID_ANALYZERS = ("blight", "autopsy", "both")


def default_jobs() -> int:
    """Return the default worker count: half the CPU count, floored at 1.

    Binary analyzers are independent subprocesses, so concurrency is bounded by
    available cores. Defaulting to ``cpu_count // 2`` leaves headroom for the
    analyzer subprocesses themselves (radare2 / angr spawn their own threads)
    rather than oversubscribing.
    """
    cpu = os.cpu_count() or 2
    return max(1, cpu // 2)


class BlightError(RuntimeError):
    """Raised when the blight binary cannot be located or run."""


class AutopsyError(RuntimeError):
    """Raised when the autopsy binary cannot be located or run."""


def _make_blight_analyzer(blight_binary: str) -> SubprocessAnalyzer:
    """Build a SubprocessAnalyzer that invokes ``blight --json <binary>``."""
    if shutil.which(blight_binary) is None and not Path(blight_binary).is_file():
        raise BlightError(
            f"blight binary {blight_binary!r} not found. Pass --blight-binary "
            "with the path to a blight executable."
        )
    return SubprocessAnalyzer(blight_binary, extra_args=["--json"])


def _make_autopsy_analyzer(autopsy_binary: str) -> SubprocessAnalyzer:
    """Build a SubprocessAnalyzer that invokes ``autopsy --format json --binary <binary>``.

    autopsy takes its target via the ``--binary PATH`` flag rather than a bare
    positional argument; because :class:`SubprocessAnalyzer` appends the binary
    path *after* ``extra_args``, listing ``"--binary"`` last makes the binary the
    value of that flag. autopsy emits the same ``{"findings": [...]}`` envelope
    blight does, so no custom output handling is required here.
    """
    if shutil.which(autopsy_binary) is None and not Path(autopsy_binary).is_file():
        raise AutopsyError(
            f"autopsy binary {autopsy_binary!r} not found. Pass --autopsy-binary "
            "with the path to an autopsy executable."
        )
    return SubprocessAnalyzer(autopsy_binary, extra_args=["--format", "json", "--binary"])


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


def _build_analyzers(
    analyzer: str,
    blight_binary: str,
    autopsy_binary: str,
) -> list[Any]:
    """Construct the analyzer callables for the requested ``analyzer`` selector.

    Returns the analyzers in a stable order (blight before autopsy) so that
    ``--analyzer both`` produces deterministic, grouped output.

    Raises:
        ValueError: If ``analyzer`` is not one of :data:`VALID_ANALYZERS`.
        BlightError / AutopsyError: If a required tool cannot be located.
    """
    if analyzer not in VALID_ANALYZERS:
        raise ValueError(
            f"unknown analyzer: {analyzer!r} (choose from {VALID_ANALYZERS})"
        )

    built: list[Any] = []
    if analyzer in ("blight", "both"):
        built.append(_make_blight_analyzer(blight_binary))
    if analyzer in ("autopsy", "both"):
        built.append(_make_autopsy_analyzer(autopsy_binary))
    return built


def analyze(
    extract_root: str | Path,
    analyzer: str = "blight",
    blight_binary: str = "blight",
    autopsy_binary: str = "autopsy",
    jobs: int | None = None,
    progress: bool = False,
    _analyzer: Any = None,
    _analyzers: list[Any] | None = None,
) -> list[Finding]:
    """Locate ELF binaries under ``extract_root`` and aggregate analyzer findings.

    Uses :func:`~binary_pipeline.find_binaries` for ELF discovery and one or more
    :class:`~binary_pipeline.SubprocessAnalyzer` instances (or test-injected
    callables) for the per-binary analysis. With ``analyzer="both"`` each ELF is
    run through both blight and autopsy and the findings are aggregated.

    Per-binary analysis is dispatched concurrently across ``jobs`` workers
    (see :func:`default_jobs`). Each binary is analyzed independently — the
    analyzers share no state — so concurrency is safe. Results are re-assembled
    in :func:`find_binaries` order, so the returned list is byte-for-byte
    identical regardless of ``jobs`` or completion order.

    Args:
        extract_root: Directory containing the extracted firmware tree.
        analyzer: Which analyzer(s) to run — one of :data:`VALID_ANALYZERS`
            (``"blight"`` (default), ``"autopsy"``, or ``"both"``).
        blight_binary: Path or name of the blight CLI (default: ``"blight"``).
        autopsy_binary: Path or name of the autopsy CLI (default: ``"autopsy"``).
        jobs: Number of binaries to analyze concurrently. ``None`` (default)
            uses :func:`default_jobs` (``cpu_count // 2``, floored at 1).
            Values < 1 are clamped to 1.
        progress: When True, emit a one-line-per-binary progress indicator to
            stderr (``[i/N] analyzing <path>``). Intended for interactive runs
            where stdout is captured to a report file.
        _analyzer: Optional override for a single analyzer callable. Used by unit
            tests to inject a mock without touching subprocess. Backwards-compat
            seam; equivalent to passing ``_analyzers=[_analyzer]``.
        _analyzers: Optional override for the full list of analyzer callables.
            Used by unit tests to exercise ``--analyzer both`` aggregation
            without subprocess. Takes precedence over ``_analyzer``.

    Returns:
        Flat list of embalmer :class:`~embalmer.models.Finding` objects with
        ``category="binary"``.

    Raises:
        BlightError: If blight is required, not on PATH, and binaries were found.
        AutopsyError: If autopsy is required, not on PATH, and binaries were found.
        ValueError: If ``analyzer`` is not a recognized selector.
    """
    root = Path(extract_root)
    binaries = find_binaries(root)
    if not binaries:
        return []

    if _analyzers is not None:
        analyzers = _analyzers
    elif _analyzer is not None:
        analyzers = [_analyzer]
    else:
        analyzers = _build_analyzers(analyzer, blight_binary, autopsy_binary)

    worker_count = default_jobs() if jobs is None else max(1, jobs)
    total = len(binaries)

    def _rel(binary: Path) -> str:
        # Compute a root-relative path for the finding record.
        try:
            return str(binary.relative_to(root))
        except ValueError:
            return str(binary)

    def _analyze_one(binary: Path) -> list[Finding]:
        try:
            binary_findings = run_pipeline([binary], analyzers)
        except SubprocessAnalyzerError as exc:
            # Surface a tool-appropriate error so the CLI can map the exit code.
            if analyzer == "autopsy":
                raise AutopsyError(str(exc)) from exc
            raise BlightError(str(exc)) from exc
        rel = _rel(binary)
        return [_to_embalmer_finding(bf, rel) for bf in binary_findings]

    # Single binary or jobs==1: stay sequential to avoid pool overhead and keep
    # tracebacks clean. Multi-binary with jobs>1 dispatches concurrently.
    if worker_count == 1 or total == 1:
        per_binary: list[list[Finding]] = []
        for index, binary in enumerate(binaries, start=1):
            if progress:
                print(f"[{index}/{total}] analyzing {_rel(binary)}",
                      file=sys.stderr, flush=True)
            per_binary.append(_analyze_one(binary))
    else:
        # Map each binary to its index so results can be re-ordered
        # deterministically regardless of completion order.
        results: dict[int, list[Finding]] = {}
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_index = {
                pool.submit(_analyze_one, binary): index
                for index, binary in enumerate(binaries)
            }
            from concurrent.futures import as_completed
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                # Let analyzer errors (BlightError/AutopsyError) propagate.
                results[index] = future.result()
                if progress:
                    completed += 1
                    print(f"[{completed}/{total}] analyzed "
                          f"{_rel(binaries[index])}",
                          file=sys.stderr, flush=True)
        per_binary = [results[i] for i in range(total)]

    findings: list[Finding] = []
    for group in per_binary:
        findings.extend(group)
    return findings
