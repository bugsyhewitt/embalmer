"""Smoke tests covering all four --checks modes against the bundled fixture
(criterion 8).

Extraction is driven by mocking the unblob seam so these run without unblob
installed; the blight invocation is replaced with a fake BinaryAnalyzer
injected via the ``_blight_analyzer`` parameter. The mocked extraction
reproduces the fixture's planted artifacts on disk so creds/binaries have
real content to walk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from binary_finding_schema import BinaryFinding
from embalmer import binaries, extract
from embalmer.cli import main
from embalmer.pipeline import run


def _plant_fixture_tree(workdir):
    """Reproduce the bundled squashfs fixture's contents on disk."""
    base = workdir / "sample-firmware.bin_extract"
    (base / "etc").mkdir(parents=True)
    (base / "bin").mkdir(parents=True)
    (base / "usr" / "lib").mkdir(parents=True)
    (base / "home" / "admin" / ".ssh").mkdir(parents=True)
    (base / "etc" / "shadow").write_text(
        "root:$6$saltsalt$3xampleHash:19000:0:99999:7:::\n"
    )
    (base / "etc" / "sample.conf").write_text(
        "admin_password=SuperSecret123\napi_key=AKIAIOSFODNN7EXAMPLE\n"
    )
    (base / "home" / "admin" / ".ssh" / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nFAKE=\n-----END RSA PRIVATE KEY-----\n"
    )
    (base / "bin" / "busybox").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    # A dpkg package database so the sbom check has real content to inventory.
    (base / "var" / "lib" / "dpkg").mkdir(parents=True)
    (base / "var" / "lib" / "dpkg" / "status").write_text(
        "Package: busybox\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 1.35.0-4\n"
        "Description: Tiny utilities for embedded systems\n"
    )


def _fake_blight_analyzer(binary: Path) -> list[BinaryFinding]:
    """Fake analyzer: always returns one CWE-120 finding."""
    return [
        BinaryFinding(
            cwe_id="CWE-120",
            function="overflow_fn",
            address="0x401000",
            evidence="overflow",
        )
    ]


@pytest.fixture(autouse=True)
def _mock_backends(monkeypatch):
    """Mock unblob extraction for every smoke test."""
    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_fixture_tree(wd))


def test_checks_extract(sample_firmware, tmp_path):
    report = run(sample_firmware, tmp_path / "w", checks="extract")
    d = report.to_dict()
    assert "extraction" in d
    assert d["extraction"]["file_count"] >= 1
    assert "credentials" not in d
    assert "binaries" not in d


def test_checks_creds(sample_firmware, tmp_path):
    report = run(sample_firmware, tmp_path / "w", checks="creds")
    d = report.to_dict()
    assert "credentials" in d
    assert any(f["category"] == "credential" for f in d["credentials"])


def test_checks_binaries(sample_firmware, tmp_path):
    report = run(
        sample_firmware, tmp_path / "w", checks="binaries",
        _blight_analyzer=_fake_blight_analyzer,
    )
    d = report.to_dict()
    assert "binaries" in d
    assert any(f["category"] == "binary" for f in d["binaries"])


def test_checks_sbom(sample_firmware, tmp_path):
    report = run(sample_firmware, tmp_path / "w", checks="sbom")
    d = report.to_dict()
    assert "sbom" in d
    assert d["sbom"]["component_count"] >= 1
    assert any(c["name"] == "busybox" for c in d["sbom"]["components"])
    assert d["sbom"]["bom"]["bomFormat"] == "CycloneDX"


def test_cli_sbom_json(sample_firmware, tmp_path, capsys):
    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "sbom",
        "--format", "json",
    ])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["sbom"]["bom"]["specVersion"] == "1.6"
    assert any(
        c["purl"].startswith("pkg:deb/busybox")
        for c in parsed["sbom"]["components"]
    )


def test_checks_all_combined(sample_firmware, tmp_path):
    report = run(
        sample_firmware, tmp_path / "w", checks="all",
        _blight_analyzer=_fake_blight_analyzer,
    )
    d = report.to_dict()
    assert "extraction" in d
    assert "credentials" in d
    assert "binaries" in d
    assert "sbom" in d


def test_cli_extract_json_exit0(sample_firmware, tmp_path, capsys):
    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "extract",
        "--format", "json",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert "extraction" in parsed
    assert "extraction_tree" in parsed["extraction"]
    assert "file_count" in parsed["extraction"]
    assert "extraction_time_ms" in parsed["extraction"]


def test_cli_creds_emits_credential(sample_firmware, tmp_path, capsys):
    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "creds",
        "--format", "json",
    ])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    creds = parsed["credentials"]
    assert any(f["category"] == "credential" and f["path"] and f["type"]
               for f in creds)


def test_cli_all_markdown(sample_firmware, tmp_path, capsys, monkeypatch):
    # For the markdown test, we need to mock the blight binary check too.
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/blight")
    # Patch the SubprocessAnalyzer._invoke to return fake findings.
    import json as _json
    from binary_pipeline import SubprocessAnalyzer

    fake_output = _json.dumps({
        "findings": [{"cwe_id": "CWE-120", "function": "main",
                      "address": "0x401000", "evidence": "overflow"}]
    })
    monkeypatch.setattr(SubprocessAnalyzer, "_invoke", lambda self, p: fake_output)

    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "all",
        "--format", "md",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("#")
    assert "Credential findings" in out
    assert "Binary findings" in out
