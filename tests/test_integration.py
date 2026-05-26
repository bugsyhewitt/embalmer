"""Integration tests against real external tools.

Marked @pytest.mark.integration so the default unit-test run can deselect them
with `-m "not integration"`. These require:
  - unblob (+ its squashfs extractor, sasquatch) on PATH
  - a real ELF binary for the blight handoff test (we use /bin/true)
The blight binary itself may not exist yet, so the blight integration test
substitutes a tiny stub script that emits the expected JSON contract — this
exercises the real subprocess path end to end without depending on blight
being built.
"""

from __future__ import annotations

import json
import os
import shutil
import stat

import pytest

from embalmer import binaries
from embalmer.cli import main
from embalmer.pipeline import run


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("unblob") is None, reason="unblob not installed")
def test_real_unblob_extract(sample_firmware, tmp_path, capsys):
    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "extract"),
        "--checks", "extract",
        "--format", "json",
    ])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    ext = parsed["extraction"]
    assert ext["file_count"] >= 1
    assert ext["extraction_tree"]
    assert ext["extraction_time_ms"] >= 0


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("unblob") is None, reason="unblob not installed")
def test_real_unblob_creds(sample_firmware, tmp_path, capsys):
    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "extract"),
        "--checks", "creds",
        "--format", "json",
    ])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    creds = parsed["credentials"]
    # the fixture plants creds in /etc/shadow and /etc/sample.conf
    assert any("shadow" in f["path"] for f in creds)
    assert any("sample.conf" in f["path"] for f in creds)


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("unblob") is None, reason="unblob not installed")
def test_real_unblob_binaries_with_stub_blight(sample_firmware, tmp_path):
    """Run the full binary pipeline against a real extraction using a stub
    blight that honours the --json contract."""
    stub = tmp_path / "blight-stub"
    stub.write_text(
        "#!/bin/sh\n"
        'echo \'{"findings":[{"cwe":"CWE-120","message":"stub","severity":"low"}]}\'\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    report = run(
        sample_firmware,
        tmp_path / "extract",
        checks="binaries",
        blight_binary=str(stub),
    )
    d = report.to_dict()
    assert "binaries" in d
    assert any(f["type"] == "CWE-120" for f in d["binaries"])


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("unblob") is None, reason="unblob not installed")
def test_real_unblob_binaries_with_stub_autopsy(sample_firmware, tmp_path):
    """Run the full binary pipeline against a real extraction using a stub
    autopsy that honours autopsy's `--format json --binary` contract.

    This exercises the real SubprocessAnalyzer path for --analyzer autopsy
    end to end without depending on autopsy (or angr) being installed.
    """
    stub = tmp_path / "autopsy-stub"
    # Stub mimics `autopsy --format json --binary <path>`: it ignores the flags
    # and emits autopsy's native JSON envelope (cwe as an int).
    stub.write_text(
        "#!/bin/sh\n"
        'echo \'{"binary":"x","checks":[416],"max_states":1000,'
        '"state_limit_exceeded":false,"findings":[{"cwe":416,'
        '"function":"free_twice","address":"0x4011aa","taint_trace":[],'
        '"evidence":"use after free"}],"finding_count":1,"error":null}\'\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    report = run(
        sample_firmware,
        tmp_path / "extract",
        checks="binaries",
        analyzer="autopsy",
        autopsy_binary=str(stub),
    )
    d = report.to_dict()
    assert "binaries" in d
    # autopsy emitted cwe=416 (int); embalmer normalizes it to "CWE-416".
    assert any(f["type"] == "CWE-416" for f in d["binaries"])
