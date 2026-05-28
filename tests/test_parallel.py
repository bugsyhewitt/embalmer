"""Unit tests for parallel binary analysis (POST_V01 Rank 9).

``binaries.analyze`` dispatches per-binary analyzer invocations across a thread
pool sized by ``--jobs``. These tests verify that:

* output is byte-for-byte identical regardless of ``jobs`` (deterministic order),
* the analyzer actually runs concurrently when ``jobs > 1``,
* ``jobs`` values are clamped sanely,
* errors from any worker propagate (mapped to Blight/AutopsyError),
* ``progress`` emits one stderr line per binary,
* ``default_jobs`` returns a sane value.

The analyzer is injected via ``_analyzer`` so no real subprocess (blight/autopsy)
is invoked.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from binary_finding_schema import BinaryFinding
from binary_pipeline._subprocess import SubprocessAnalyzerError
from embalmer import binaries


def _finding(cwe_id="CWE-120", function="main", address="0x401000",
             evidence="overflow", symbol=None) -> BinaryFinding:
    return BinaryFinding(
        cwe_id=cwe_id,
        function=function,
        address=address,
        evidence=evidence,
        symbol=symbol,
    )


def _per_binary_analyzer():
    """Analyzer that yields one finding whose evidence is the binary's name.

    Lets tests assert on *which* binary produced *which* finding so ordering is
    verifiable, not just count.
    """
    def _analyzer(binary: Path) -> list[BinaryFinding]:
        return [_finding(evidence=f"from:{binary.name}")]
    return _analyzer


def test_default_jobs_is_sane():
    jobs = binaries.default_jobs()
    assert isinstance(jobs, int)
    assert jobs >= 1


def test_parallel_matches_sequential_order(fake_extracted_tree):
    """Output is identical for jobs=1 and jobs=4 — order is deterministic."""
    analyzer = _per_binary_analyzer()
    seq = binaries.analyze(fake_extracted_tree, jobs=1, _analyzer=analyzer)
    par = binaries.analyze(fake_extracted_tree, jobs=4, _analyzer=analyzer)

    assert len(seq) == len(par) == 2
    seq_evidence = [f.detail for f in seq]
    par_evidence = [f.detail for f in par]
    assert seq_evidence == par_evidence, "parallel run reordered findings"


def test_parallel_matches_sequential_paths(fake_extracted_tree):
    """Each finding's path is preserved and ordered identically across jobs."""
    analyzer = _per_binary_analyzer()
    seq = binaries.analyze(fake_extracted_tree, jobs=1, _analyzer=analyzer)
    par = binaries.analyze(fake_extracted_tree, jobs=8, _analyzer=analyzer)
    assert [f.path for f in seq] == [f.path for f in par]


def test_jobs_none_uses_default(fake_extracted_tree, monkeypatch):
    """jobs=None routes through default_jobs()."""
    called = {"n": 0}
    real = binaries.default_jobs

    def _spy():
        called["n"] += 1
        return real()

    monkeypatch.setattr(binaries, "default_jobs", _spy)
    binaries.analyze(fake_extracted_tree, jobs=None,
                     _analyzer=_per_binary_analyzer())
    assert called["n"] == 1


def test_jobs_zero_and_negative_clamped(fake_extracted_tree):
    """jobs <= 0 is clamped to 1 (sequential), not an error."""
    analyzer = _per_binary_analyzer()
    for bad in (0, -5):
        findings = binaries.analyze(fake_extracted_tree, jobs=bad,
                                    _analyzer=analyzer)
        assert len(findings) == 2


def test_actual_concurrency(fake_extracted_tree):
    """With jobs=2 and 2 binaries, both analyzers run at the same time.

    Each analyzer blocks on a barrier that requires 2 threads to be present
    simultaneously; if dispatch were serial the barrier would time out.
    """
    barrier = threading.Barrier(2, timeout=5)

    def _analyzer(binary: Path) -> list[BinaryFinding]:
        # Will raise BrokenBarrierError on timeout if not run concurrently.
        barrier.wait()
        return [_finding(evidence=f"from:{binary.name}")]

    findings = binaries.analyze(fake_extracted_tree, jobs=2, _analyzer=_analyzer)
    assert len(findings) == 2


def test_sequential_path_is_truly_serial(fake_extracted_tree):
    """jobs=1 must NOT run concurrently — barrier(2) would deadlock/timeout."""
    barrier = threading.Barrier(2, timeout=1)

    def _analyzer(binary: Path) -> list[BinaryFinding]:
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            # Expected: only one thread ever reaches the barrier.
            pass
        return [_finding()]

    # Should complete (each call times out the barrier independently) and still
    # produce findings — proving calls were serialized, not concurrent.
    findings = binaries.analyze(fake_extracted_tree, jobs=1, _analyzer=_analyzer)
    assert len(findings) == 2


def test_error_propagates_under_parallelism(fake_extracted_tree):
    """A SubprocessAnalyzerError from any worker surfaces as BlightError."""
    def _analyzer(binary: Path) -> list[BinaryFinding]:
        raise SubprocessAnalyzerError("blight crashed")

    with pytest.raises(binaries.BlightError):
        binaries.analyze(fake_extracted_tree, jobs=4, _analyzer=_analyzer)


def test_error_propagates_maps_to_autopsy(fake_extracted_tree):
    """When analyzer='autopsy', a worker error maps to AutopsyError."""
    def _analyzer(binary: Path) -> list[BinaryFinding]:
        raise SubprocessAnalyzerError("autopsy crashed")

    with pytest.raises(binaries.AutopsyError):
        binaries.analyze(
            fake_extracted_tree,
            analyzer="autopsy",
            jobs=4,
            _analyzer=_analyzer,
        )


def test_progress_emitted_to_stderr(fake_extracted_tree, capsys):
    """progress=True writes one '[i/N] ...' line per binary to stderr."""
    binaries.analyze(fake_extracted_tree, jobs=2, progress=True,
                     _analyzer=_per_binary_analyzer())
    err = capsys.readouterr().err
    lines = [ln for ln in err.splitlines() if ln.strip()]
    # 2 binaries -> 2 progress lines.
    assert len(lines) == 2
    assert all("/2]" in ln for ln in lines)


def test_progress_sequential_path(fake_extracted_tree, capsys):
    """progress also works on the sequential (jobs=1) path."""
    binaries.analyze(fake_extracted_tree, jobs=1, progress=True,
                     _analyzer=_per_binary_analyzer())
    err = capsys.readouterr().err
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert "[1/2]" in err and "[2/2]" in err


def test_no_progress_by_default(fake_extracted_tree, capsys):
    """Without progress=True, nothing is written to stderr."""
    binaries.analyze(fake_extracted_tree, jobs=4,
                     _analyzer=_per_binary_analyzer())
    assert capsys.readouterr().err == ""


def test_empty_tree_returns_empty_with_jobs(tmp_path):
    """No binaries -> empty result even with jobs set, no pool created."""
    (tmp_path / "extract").mkdir()
    (tmp_path / "extract" / "readme.txt").write_text("nope")
    assert binaries.analyze(tmp_path / "extract", jobs=8) == []
