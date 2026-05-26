"""Unit tests for the extraction layer (unblob mocked)."""

from __future__ import annotations

import pytest

from embalmer import extract
from embalmer.models import ExtractionResult


def _plant_tree(workdir):
    """Simulate what unblob writes into the workdir."""
    ext = workdir / "fw_extract" / "etc"
    ext.mkdir(parents=True)
    (ext / "shadow").write_text("root:$6$x$y:0:0:::\n")
    (workdir / "fw_extract" / "bin").mkdir(parents=True)
    (workdir / "fw_extract" / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 64)


def test_extract_builds_tree_and_counts(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"

    def fake_run(fw, wd):
        _plant_tree(wd)

    monkeypatch.setattr(extract, "_run_unblob", fake_run)

    result = extract.extract(firmware, workdir)
    assert isinstance(result, ExtractionResult)
    assert result.file_count == 2
    assert result.extraction_time_ms >= 0
    assert result.extract_root == str(workdir)
    # nested tree structure present
    d = result.to_dict()
    assert "extraction_tree" in d
    assert "fw_extract" in d["extraction_tree"]


def test_extract_missing_firmware_raises(tmp_path):
    with pytest.raises(extract.ExtractionError):
        extract.extract(tmp_path / "nope.bin", tmp_path / "work")


def test_extract_tree_records_file_sizes(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"
    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_tree(wd))
    result = extract.extract(firmware, workdir)
    etc = result.extraction_tree["fw_extract"]["etc"]
    assert etc["shadow"]["_type"] == "file"
    assert etc["shadow"]["size"] > 0
