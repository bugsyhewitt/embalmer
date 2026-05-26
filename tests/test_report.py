"""Unit tests for report rendering (criterion 7)."""

from __future__ import annotations

import json

from embalmer.models import ExtractionResult, Finding, Report
from embalmer.report import render, to_json, to_markdown


def _sample_report() -> Report:
    return Report(
        firmware="router.bin",
        checks=["extract", "creds", "binaries"],
        extraction=ExtractionResult(
            extraction_tree={"etc": {"shadow": {"_type": "file", "size": 42}}},
            file_count=1,
            extraction_time_ms=12,
            extract_root="/tmp/work",
        ),
        credentials=[
            Finding(category="credential", path="etc/shadow", type="password_hash",
                    detail="hash", severity="high"),
        ],
        binaries=[
            Finding(category="binary", path="bin/busybox", type="CWE-120",
                    detail="overflow", severity="high"),
        ],
    )


def test_json_roundtrip_has_all_sections():
    report = _sample_report()
    parsed = json.loads(to_json(report))
    assert parsed["firmware"] == "router.bin"
    assert "extraction" in parsed
    assert parsed["extraction"]["file_count"] == 1
    assert parsed["credentials"][0]["category"] == "credential"
    assert parsed["binaries"][0]["type"] == "CWE-120"


def test_markdown_contains_same_data():
    report = _sample_report()
    md = to_markdown(report)
    assert "router.bin" in md
    assert "Extraction" in md
    assert "Credential findings" in md
    assert "Binary findings" in md
    assert "etc/shadow" in md
    assert "CWE-120" in md
    assert "shadow" in md


def test_render_dispatch():
    report = _sample_report()
    assert render(report, "json").lstrip().startswith("{")
    assert render(report, "md").startswith("#")


def test_omitted_checks_absent_from_json():
    report = Report(firmware="x.bin", checks=["extract"],
                    extraction=ExtractionResult({}, 0, 0, "/tmp"))
    parsed = json.loads(to_json(report))
    assert "extraction" in parsed
    assert "credentials" not in parsed
    assert "binaries" not in parsed
