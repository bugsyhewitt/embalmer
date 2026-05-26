"""Unit tests for the binary analysis handoff (criterion 5).

The blight invocation is tested by injecting a mock analyzer via the
``_analyzer`` parameter. Tests that previously monkeypatched the internal
``_run_blight`` seam have been updated to use the new injection point.
A real-binary integration test lives in test_integration.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from binary_finding_schema import BinaryFinding
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


def make_fake_analyzer(*bf_list: BinaryFinding):
    """Return a callable that returns the given BinaryFindings for any binary."""
    def _analyzer(binary: Path) -> list[BinaryFinding]:
        return list(bf_list)
    return _analyzer


def test_find_binaries_locates_elf(fake_extracted_tree):
    found = binaries.find_binaries(fake_extracted_tree)
    names = {p.name for p in found}
    assert "busybox" in names
    assert "libcrypto.so" in names
    # the shell script is not ELF
    assert "init" not in names


def test_analyze_aggregates_blight_findings(fake_extracted_tree):
    """analyze() runs the analyzer over each ELF and aggregates findings."""
    fake = make_fake_analyzer(
        _finding(cwe_id="CWE-120", evidence="buffer overflow risk")
    )
    findings = binaries.analyze(fake_extracted_tree, _analyzer=fake)
    assert findings, "expected aggregated blight findings"
    assert all(f.category == "binary" for f in findings)
    # 2 ELF files in fake_extracted_tree * 1 finding each = 2 findings
    assert len(findings) == 2
    assert all(f.type == "CWE-120" for f in findings)


def test_analyze_propagates_cwe_id_as_type(fake_extracted_tree):
    """The finding type field carries the CWE-N string."""
    fake = make_fake_analyzer(_finding(cwe_id="CWE-78"))
    findings = binaries.analyze(fake_extracted_tree, _analyzer=fake)
    assert all(f.type == "CWE-78" for f in findings)


def test_analyze_finding_has_path_and_category(fake_extracted_tree):
    """Each finding records the relative binary path and category='binary'."""
    fake = make_fake_analyzer(_finding())
    findings = binaries.analyze(fake_extracted_tree, _analyzer=fake)
    for f in findings:
        assert f.category == "binary"
        assert f.path  # non-empty relative path


def test_analyze_finding_extra_includes_function_and_address(fake_extracted_tree):
    """function and address from BinaryFinding appear in the extra dict."""
    fake = make_fake_analyzer(
        _finding(function="copy_it", address="0x40114a", symbol="strcpy")
    )
    findings = binaries.analyze(fake_extracted_tree, _analyzer=fake)
    assert findings[0].extra.get("function") == "copy_it"
    assert findings[0].extra.get("address") == "0x40114a"
    assert findings[0].extra.get("symbol") == "strcpy"


def test_analyze_no_binaries_returns_empty(tmp_path):
    (tmp_path / "extract").mkdir()
    (tmp_path / "extract" / "readme.txt").write_text("not a binary")
    assert binaries.analyze(tmp_path / "extract") == []


def test_analyze_missing_blight_raises(fake_extracted_tree, monkeypatch):
    """BlightError raised when blight is not on PATH and binaries exist."""
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: None)
    with pytest.raises(binaries.BlightError):
        binaries.analyze(
            fake_extracted_tree,
            blight_binary="/nonexistent/path/to/blight",
        )


def test_analyze_empty_findings_from_analyzer(fake_extracted_tree):
    """Analyzer returning empty list produces empty result."""
    fake = make_fake_analyzer()  # returns no findings
    findings = binaries.analyze(fake_extracted_tree, _analyzer=fake)
    assert findings == []


def test_find_binaries_function_accessible():
    """find_binaries is re-exported from binary_pipeline, accessible as binaries.find_binaries."""
    assert callable(binaries.find_binaries)
