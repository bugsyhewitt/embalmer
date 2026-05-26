"""Unit tests for the autopsy analyzer handoff and ``--analyzer`` selector.

These cover the Phase 2 improvement: ``--analyzer {blight,autopsy,both}``.

The autopsy subprocess is always mocked here — angr is never imported, and the
real autopsy CLI is never invoked. We exercise three layers:

  1. ``binaries.analyze(analyzer="autopsy")`` with an injected analyzer callable
     (the same ``_analyzer`` seam blight uses).
  2. ``binaries.analyze(analyzer="both")`` aggregation via the ``_analyzers``
     list seam.
  3. The real ``SubprocessAnalyzer`` wiring for autopsy, with ``_invoke``
     monkeypatched to return canned autopsy JSON — this proves embalmer parses
     autopsy's native ``{"findings": [{"cwe": <int>, ...}]}`` envelope without a
     bespoke parser.
  4. End-to-end through ``pipeline.run`` and the CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from binary_finding_schema import BinaryFinding
from binary_pipeline import SubprocessAnalyzer

from embalmer import binaries
from embalmer.cli import main
from embalmer.pipeline import run


def _bf(cwe_id="CWE-119", function="vuln", address="0x401abc",
        evidence="attacker-controlled offset", symbol=None) -> BinaryFinding:
    return BinaryFinding(
        cwe_id=cwe_id,
        function=function,
        address=address,
        evidence=evidence,
        symbol=symbol,
    )


def _make_fake_analyzer(*bf_list: BinaryFinding):
    def _analyzer(binary: Path) -> list[BinaryFinding]:
        return list(bf_list)
    return _analyzer


# A canned autopsy JSON report (autopsy's native shape: cwe as int, address as
# hex string, a findings envelope, a taint_trace). This is what `autopsy
# --format json --binary <path>` prints to stdout.
AUTOPSY_JSON = json.dumps({
    "binary": "/extract/bin/busybox",
    "checks": [119],
    "max_states": 1000,
    "state_limit_exceeded": False,
    "findings": [
        {
            "cwe": 119,
            "function": "handle_request",
            "address": "0x401abc",
            "taint_trace": [
                {"address": "0x401100", "description": "read() into buf"},
                {"address": "0x401abc", "description": "indexed write, no bound"},
            ],
            "evidence": "attacker-controlled offset reaches memory write",
        }
    ],
    "finding_count": 1,
    "error": None,
})


# --- analyzer="autopsy" via injected callable -----------------------------

def test_analyze_autopsy_aggregates_findings(fake_extracted_tree):
    """analyze(analyzer='autopsy') runs the injected analyzer over each ELF."""
    fake = _make_fake_analyzer(_bf(cwe_id="CWE-416", evidence="use-after-free"))
    findings = binaries.analyze(
        fake_extracted_tree, analyzer="autopsy", _analyzer=fake,
    )
    assert findings, "expected aggregated autopsy findings"
    assert all(f.category == "binary" for f in findings)
    # 2 ELF files in fake_extracted_tree * 1 finding each = 2 findings
    assert len(findings) == 2
    assert all(f.type == "CWE-416" for f in findings)


def test_analyze_autopsy_carries_function_and_address(fake_extracted_tree):
    fake = _make_fake_analyzer(
        _bf(function="handle_request", address="0x401abc")
    )
    findings = binaries.analyze(
        fake_extracted_tree, analyzer="autopsy", _analyzer=fake,
    )
    assert findings[0].extra.get("function") == "handle_request"
    assert findings[0].extra.get("address") == "0x401abc"


# --- analyzer="both" aggregation ------------------------------------------

def test_analyze_both_aggregates_two_analyzers(fake_extracted_tree):
    """analyze(analyzer='both') runs every injected analyzer over every ELF."""
    blight_like = _make_fake_analyzer(_bf(cwe_id="CWE-120", evidence="overflow"))
    autopsy_like = _make_fake_analyzer(_bf(cwe_id="CWE-416", evidence="uaf"))
    findings = binaries.analyze(
        fake_extracted_tree,
        analyzer="both",
        _analyzers=[blight_like, autopsy_like],
    )
    # 2 ELF files * 2 analyzers * 1 finding each = 4 findings
    assert len(findings) == 4
    types = {f.type for f in findings}
    assert types == {"CWE-120", "CWE-416"}


def test_analyze_both_empty_when_no_binaries(tmp_path):
    (tmp_path / "extract").mkdir()
    (tmp_path / "extract" / "notes.txt").write_text("not a binary")
    assert binaries.analyze(
        tmp_path / "extract",
        analyzer="both",
        _analyzers=[_make_fake_analyzer(_bf())],
    ) == []


# --- real SubprocessAnalyzer wiring for autopsy (subprocess mocked) -------

def test_autopsy_subprocess_parses_native_json(fake_extracted_tree, monkeypatch):
    """The autopsy SubprocessAnalyzer parses autopsy's native JSON envelope.

    autopsy is reported as present on PATH and its _invoke seam returns canned
    JSON, so neither autopsy nor angr is required to run this test.
    """
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/autopsy")
    monkeypatch.setattr(
        SubprocessAnalyzer, "_invoke", lambda self, p: AUTOPSY_JSON
    )

    findings = binaries.analyze(fake_extracted_tree, analyzer="autopsy")
    assert findings, "expected findings parsed from autopsy JSON"
    # autopsy emits cwe=119 (int); the schema normalizes it to "CWE-119".
    assert all(f.type == "CWE-119" for f in findings)
    assert all(f.category == "binary" for f in findings)
    # 2 ELF files * 1 finding each.
    assert len(findings) == 2
    assert findings[0].detail == "attacker-controlled offset reaches memory write"


def test_autopsy_invokes_correct_argv(fake_extracted_tree, monkeypatch):
    """The autopsy analyzer is configured as `autopsy --format json --binary`."""
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/autopsy")
    captured: list[list[str]] = []

    def _fake_run(cmd, *a, **k):
        captured.append(cmd)
        class _P:
            returncode = 0
            stdout = AUTOPSY_JSON
            stderr = ""
        return _P()

    import binary_pipeline._subprocess as _sub
    monkeypatch.setattr(_sub.subprocess, "run", _fake_run)

    binaries.analyze(fake_extracted_tree, analyzer="autopsy")
    assert captured, "expected autopsy subprocess invocation"
    for cmd in captured:
        assert cmd[0] == "autopsy"
        assert cmd[1:4] == ["--format", "json", "--binary"]
        # the binary path is appended last
        assert cmd[-1].endswith((".so", "busybox"))


def test_autopsy_missing_binary_raises(fake_extracted_tree, monkeypatch):
    """AutopsyError raised when autopsy is not on PATH and binaries exist."""
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: None)
    with pytest.raises(binaries.AutopsyError):
        binaries.analyze(
            fake_extracted_tree,
            analyzer="autopsy",
            autopsy_binary="/nonexistent/autopsy",
        )


def test_unknown_analyzer_raises(fake_extracted_tree):
    with pytest.raises(ValueError):
        binaries.analyze(fake_extracted_tree, analyzer="ghost")


# --- pipeline + CLI integration -------------------------------------------

def test_pipeline_autopsy_selector(sample_firmware, monkeypatch, tmp_path):
    """pipeline.run threads analyzer='autopsy' through to binaries.analyze."""
    from embalmer import extract

    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_elf(wd))
    report = run(
        sample_firmware, tmp_path / "w", checks="binaries", analyzer="autopsy",
        _binary_analyzers=[_make_fake_analyzer(_bf(cwe_id="CWE-78"))],
    )
    d = report.to_dict()
    assert "binaries" in d
    assert any(f["type"] == "CWE-78" for f in d["binaries"])


def test_cli_analyzer_both_aggregates(sample_firmware, monkeypatch, tmp_path, capsys):
    """CLI --analyzer both runs both tools via the real SubprocessAnalyzer."""
    from embalmer import extract

    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_elf(wd))
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/tool")

    blight_json = json.dumps({
        "findings": [{"cwe_id": "CWE-120", "function": "f",
                      "address": "0x401000", "evidence": "overflow"}]
    })

    def _fake_invoke(self, p):
        # Distinguish the two tools by their configured extra_args.
        if "--format" in self.extra_args:  # autopsy
            return AUTOPSY_JSON
        return blight_json  # blight

    monkeypatch.setattr(SubprocessAnalyzer, "_invoke", _fake_invoke)

    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "binaries",
        "--analyzer", "both",
        "--format", "json",
    ])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    types = {f["type"] for f in parsed["binaries"]}
    # blight CWE-120 + autopsy CWE-119 both present.
    assert "CWE-120" in types
    assert "CWE-119" in types


def test_cli_default_analyzer_is_blight(sample_firmware, monkeypatch, tmp_path, capsys):
    """Backwards compat: with no --analyzer flag, only blight runs."""
    from embalmer import extract

    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_elf(wd))
    monkeypatch.setattr(binaries.shutil, "which", lambda _b: "/usr/bin/blight")

    seen_argv: list[list[str]] = []

    def _fake_run(cmd, *a, **k):
        seen_argv.append(cmd)
        class _P:
            returncode = 0
            stdout = json.dumps({"findings": [
                {"cwe_id": "CWE-120", "function": "f",
                 "address": "0x401000", "evidence": "overflow"}]})
            stderr = ""
        return _P()

    import binary_pipeline._subprocess as _sub
    monkeypatch.setattr(_sub.subprocess, "run", _fake_run)

    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "binaries",
        "--format", "json",
    ])
    assert rc == 0
    # Only blight was invoked — no autopsy in any argv.
    assert seen_argv
    assert all(cmd[0] == "blight" for cmd in seen_argv)
    assert not any("autopsy" in cmd[0] for cmd in seen_argv)


def _plant_elf(workdir):
    """Minimal extraction tree with two ELF placeholders."""
    base = Path(workdir) / "fw.bin_extract"
    (base / "bin").mkdir(parents=True)
    (base / "usr" / "lib").mkdir(parents=True)
    (base / "bin" / "busybox").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    (base / "usr" / "lib" / "libc.so").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
