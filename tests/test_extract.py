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


def _plant_binwalk_tree(workdir):
    """Simulate what binwalk writes — a different layout root, same shape."""
    ext = workdir / "_fw.extracted" / "etc"
    ext.mkdir(parents=True)
    (ext / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")


# --- extractor selection ---------------------------------------------------


def test_extract_default_is_auto_and_uses_unblob_when_it_works(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"
    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_tree(wd))
    # binwalk must NOT be invoked when unblob succeeds.
    monkeypatch.setattr(
        extract,
        "_run_binwalk",
        lambda fw, wd: pytest.fail("binwalk should not run when unblob succeeds"),
    )
    result = extract.extract(firmware, workdir)  # default extractor="auto"
    assert result.extractor_used == "unblob"
    assert result.file_count == 2


def test_extract_explicit_unblob_does_not_fall_back(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"

    def fail_unblob(fw, wd):
        raise extract.ExtractionError("unblob boom")

    monkeypatch.setattr(extract, "_run_unblob", fail_unblob)
    monkeypatch.setattr(
        extract,
        "_run_binwalk",
        lambda fw, wd: pytest.fail("binwalk must not run for extractor='unblob'"),
    )
    with pytest.raises(extract.ExtractionError):
        extract.extract(firmware, workdir, extractor="unblob")


def test_extract_explicit_binwalk_skips_unblob(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"
    monkeypatch.setattr(
        extract,
        "_run_unblob",
        lambda fw, wd: pytest.fail("unblob must not run for extractor='binwalk'"),
    )
    monkeypatch.setattr(extract, "_run_binwalk", lambda fw, wd: _plant_binwalk_tree(wd))
    result = extract.extract(firmware, workdir, extractor="binwalk")
    assert result.extractor_used == "binwalk"
    assert result.file_count == 1
    assert "_fw.extracted" in result.extraction_tree


def test_auto_falls_back_to_binwalk_when_unblob_errors(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"

    def fail_unblob(fw, wd):
        wd.mkdir(parents=True, exist_ok=True)
        raise extract.ExtractionError("unblob exited 1 and produced no output")

    monkeypatch.setattr(extract, "_run_unblob", fail_unblob)
    monkeypatch.setattr(extract, "_run_binwalk", lambda fw, wd: _plant_binwalk_tree(wd))
    result = extract.extract(firmware, workdir, extractor="auto")
    assert result.extractor_used == "binwalk"
    assert result.file_count == 1


def test_auto_falls_back_to_binwalk_when_unblob_empty(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"

    # unblob "succeeds" but leaves an empty workdir (format not recognized).
    def empty_unblob(fw, wd):
        wd.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(extract, "_run_unblob", empty_unblob)
    monkeypatch.setattr(extract, "_run_binwalk", lambda fw, wd: _plant_binwalk_tree(wd))
    result = extract.extract(firmware, workdir, extractor="auto")
    assert result.extractor_used == "binwalk"
    assert "_fw.extracted" in result.extraction_tree


def test_auto_clears_unblob_scaffolding_before_binwalk(tmp_path, monkeypatch):
    """A partial unblob run leaves empty dirs; binwalk's tree must be clean."""
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"

    def partial_unblob(fw, wd):
        # only empty scaffolding, no files -> treated as empty
        (wd / "unblob_leftover").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(extract, "_run_unblob", partial_unblob)
    monkeypatch.setattr(extract, "_run_binwalk", lambda fw, wd: _plant_binwalk_tree(wd))
    result = extract.extract(firmware, workdir, extractor="auto")
    assert "unblob_leftover" not in result.extraction_tree
    assert "_fw.extracted" in result.extraction_tree


def test_auto_surfaces_binwalk_error_when_both_fail(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"
    monkeypatch.setattr(
        extract,
        "_run_unblob",
        lambda fw, wd: (_ for _ in ()).throw(extract.ExtractionError("unblob fail")),
    )

    def fail_binwalk(fw, wd):
        raise extract.ExtractionError("binwalk also failed")

    monkeypatch.setattr(extract, "_run_binwalk", fail_binwalk)
    with pytest.raises(extract.ExtractionError, match="binwalk also failed"):
        extract.extract(firmware, workdir, extractor="auto")


def test_extract_rejects_unknown_extractor(tmp_path):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    with pytest.raises(extract.ExtractionError, match="unknown extractor"):
        extract.extract(firmware, tmp_path / "work", extractor="nonsense")


def test_run_binwalk_missing_binary_raises(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    monkeypatch.setattr(extract.shutil, "which", lambda _b: None)
    with pytest.raises(extract.ExtractionError, match="binwalk"):
        extract._run_binwalk(firmware, tmp_path / "work")


def test_extractor_used_in_result_dict(tmp_path, monkeypatch):
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00" * 32)
    workdir = tmp_path / "work"
    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_tree(wd))
    result = extract.extract(firmware, workdir)
    assert result.to_dict()["extractor_used"] == "unblob"
