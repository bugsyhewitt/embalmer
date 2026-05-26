"""Unit tests for the blight handoff (criterion 5).

The blight subprocess boundary is mocked here; a real-binary integration test
lives in test_integration.py marked @pytest.mark.integration.
"""

from __future__ import annotations

import pytest

from embalmer import binaries


def test_find_binaries_locates_elf(fake_extracted_tree):
    found = binaries.find_binaries(fake_extracted_tree)
    names = {p.name for p in found}
    assert "busybox" in names
    assert "libcrypto.so" in names
    # the shell script is not ELF
    assert "init" not in names


def test_analyze_aggregates_blight_findings(fake_extracted_tree, monkeypatch):
    # Mock the blight presence check and its JSON output.
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/blight")

    def fake_run_blight(blight_binary, target):
        return {
            "findings": [
                {
                    "cwe": "CWE-120",
                    "message": "buffer overflow risk",
                    "severity": "high",
                    "offset": "0x401000",
                }
            ]
        }

    monkeypatch.setattr(binaries, "_run_blight", fake_run_blight)

    findings = binaries.analyze(fake_extracted_tree, blight_binary="blight")
    assert findings, "expected aggregated blight findings"
    assert all(f.category == "binary" for f in findings)
    cwe = findings[0]
    assert cwe.type == "CWE-120"
    assert cwe.severity == "high"
    assert cwe.extra.get("offset") == "0x401000"


def test_analyze_accepts_bare_list_shape(fake_extracted_tree, monkeypatch):
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/blight")
    monkeypatch.setattr(
        binaries,
        "_run_blight",
        lambda b, t: [{"id": "CWE-78", "detail": "command injection"}],
    )
    findings = binaries.analyze(fake_extracted_tree)
    assert any(f.type == "CWE-78" for f in findings)


def test_analyze_unknown_shape_preserved(fake_extracted_tree, monkeypatch):
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/blight")
    monkeypatch.setattr(binaries, "_run_blight", lambda b, t: {"weird": 1})
    findings = binaries.analyze(fake_extracted_tree)
    assert findings
    assert findings[0].type == "blight_raw"
    assert findings[0].extra["raw"] == {"weird": 1}


def test_analyze_no_binaries_returns_empty(tmp_path):
    (tmp_path / "extract").mkdir()
    (tmp_path / "extract" / "readme.txt").write_text("not a binary")
    assert binaries.analyze(tmp_path / "extract") == []


def test_analyze_missing_blight_raises(fake_extracted_tree, monkeypatch):
    # blight not on PATH; binaries exist in the tree -> should raise.
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: None)
    with pytest.raises(binaries.BlightError):
        binaries.analyze(
            fake_extracted_tree,
            blight_binary="/nonexistent/path/to/blight",
        )
