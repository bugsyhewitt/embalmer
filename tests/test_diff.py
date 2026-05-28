"""Tests for baseline diff mode (POST_V01 Rank 5 — firmware upgrade comparison).

These tests are pure: they construct `Report` objects directly and feed loaded
baseline dicts in, so no extraction, blight, or network enrichment runs. The CLI
smoke test mocks the unblob seam the same way the existing smoke tests do.
"""

from __future__ import annotations

import json

import pytest

from embalmer import diff as diffmod
from embalmer.diff import (
    BaselineError,
    compute_diff,
    diff_findings,
    diff_sbom,
    load_baseline,
)
from embalmer.diff import render as render_diff
from embalmer.models import Finding, Report


# --------------------------------------------------------------------------- #
# load_baseline
# --------------------------------------------------------------------------- #


def test_load_baseline_reads_valid_report(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"firmware": "old.bin", "checks": ["creds"]}))
    data = load_baseline(path)
    assert data["firmware"] == "old.bin"


def test_load_baseline_missing_file(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "nope.json")


def test_load_baseline_invalid_json(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text("{not json")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_baseline_not_a_report(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"some": "object"}))
    with pytest.raises(BaselineError):
        load_baseline(path)


# --------------------------------------------------------------------------- #
# diff_findings
# --------------------------------------------------------------------------- #


def _cred(path, key, detail="", severity="high"):
    return Finding(
        category="credential", path=path, type="hardcoded-secret",
        detail=detail, severity=severity, extra={"key": key},
    ).to_dict()


def test_diff_findings_added_removed_unchanged():
    before = [_cred("/etc/a.conf", "pw1"), _cred("/etc/b.conf", "pw2")]
    after = [_cred("/etc/b.conf", "pw2"), _cred("/etc/c.conf", "pw3")]

    delta = diff_findings(before, after)

    assert [f["path"] for f in delta.added] == ["/etc/c.conf"]
    assert [f["path"] for f in delta.removed] == ["/etc/a.conf"]
    assert [f["path"] for f in delta.unchanged] == ["/etc/b.conf"]
    assert not delta.severity_changed


def test_diff_findings_severity_change_is_not_add_remove():
    before = [_cred("/etc/a.conf", "pw1", severity="medium")]
    after = [_cred("/etc/a.conf", "pw1", severity="critical")]

    delta = diff_findings(before, after)

    assert not delta.added
    assert not delta.removed
    assert not delta.unchanged
    assert len(delta.severity_changed) == 1
    entry = delta.severity_changed[0]
    assert entry["from"] == "medium"
    assert entry["to"] == "critical"


def test_diff_findings_binary_identity_uses_function_and_address():
    def b(path, fn, addr, sev="high"):
        return Finding(
            category="binary", path=path, type="CWE-120",
            severity=sev, extra={"function": fn, "address": addr},
        ).to_dict()

    before = [b("/bin/x", "vuln", "0x1000")]
    # same binary, CWE fixed at that address; a new one appears elsewhere
    after = [b("/bin/x", "other", "0x2000")]

    delta = diff_findings(before, after)
    assert len(delta.added) == 1
    assert len(delta.removed) == 1


# --------------------------------------------------------------------------- #
# diff_sbom
# --------------------------------------------------------------------------- #


def _comp(name, version, source="deb"):
    return {"source": source, "name": name, "version": version,
            "purl": f"pkg:{source}/{name}@{version}"}


def test_diff_sbom_version_bump_is_changed_not_add_remove():
    before = [_comp("busybox", "1.35.0"), _comp("openssl", "3.0.0")]
    after = [_comp("busybox", "1.36.1"), _comp("openssl", "3.0.0")]

    delta = diff_sbom(before, after)

    assert not delta.added
    assert not delta.removed
    assert [c["name"] for c in delta.unchanged] == ["openssl"]
    assert len(delta.changed) == 1
    assert delta.changed[0]["from"] == "1.35.0"
    assert delta.changed[0]["to"] == "1.36.1"


def test_diff_sbom_add_and_remove():
    before = [_comp("curl", "8.0.0")]
    after = [_comp("zlib", "1.3")]

    delta = diff_sbom(before, after)
    assert [c["name"] for c in delta.added] == ["zlib"]
    assert [c["name"] for c in delta.removed] == ["curl"]


# --------------------------------------------------------------------------- #
# compute_diff (report-level)
# --------------------------------------------------------------------------- #


def test_compute_diff_full_report():
    baseline = {
        "firmware": "v1.bin",
        "checks": ["creds"],
        "credentials": [_cred("/etc/a.conf", "pw1", severity="high")],
    }
    current = Report(
        firmware="v2.bin",
        checks=["creds"],
        credentials=[Finding(
            category="credential", path="/etc/a.conf", type="hardcoded-secret",
            severity="high", extra={"key": "pw1"},
        )],
    )

    diff = compute_diff(baseline, current)
    d = diff.to_dict()["diff"]

    assert d["baseline_firmware"] == "v1.bin"
    assert d["current_firmware"] == "v2.bin"
    assert d["findings"]["credentials"]["counts"]["unchanged"] == 1
    assert d["findings"]["credentials"]["counts"]["added"] == 0


def test_compute_diff_section_only_in_current_is_all_added():
    baseline = {"firmware": "v1.bin", "checks": ["extract"]}
    current = Report(
        firmware="v2.bin",
        checks=["creds"],
        credentials=[Finding(
            category="credential", path="/etc/a.conf", type="hardcoded-secret",
            severity="high", extra={"key": "pw1"},
        )],
    )
    diff = compute_diff(baseline, current)
    creds_delta = diff.to_dict()["diff"]["findings"]["credentials"]
    assert creds_delta["counts"]["added"] == 1
    assert creds_delta["counts"]["removed"] == 0


def test_compute_diff_sbom_section():
    baseline = {
        "firmware": "v1.bin", "checks": ["sbom"],
        "sbom": {"components": [_comp("busybox", "1.35.0", source="dpkg")]},
    }
    from embalmer.sbom import Sbom, Component

    current = Report(
        firmware="v2.bin", checks=["sbom"],
        sbom=Sbom(components=[
            Component(source="dpkg", name="busybox", version="1.36.1"),
        ]),
    )
    diff = compute_diff(baseline, current)
    sbom_delta = diff.to_dict()["diff"]["sbom"]
    assert sbom_delta["counts"]["changed"] == 1
    assert sbom_delta["changed"][0]["to"] == "1.36.1"


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #


def test_render_diff_json_roundtrips():
    baseline = {"firmware": "v1.bin", "checks": ["creds"],
                "credentials": []}
    current = Report(firmware="v2.bin", checks=["creds"], credentials=[])
    diff = compute_diff(baseline, current)
    out = render_diff(diff, "json")
    parsed = json.loads(out)
    assert parsed["diff"]["current_firmware"] == "v2.bin"


def test_render_diff_markdown_lists_changes():
    baseline = {
        "firmware": "v1.bin", "checks": ["creds"],
        "credentials": [_cred("/etc/old.conf", "gone", detail="old secret")],
    }
    current = Report(
        firmware="v2.bin", checks=["creds"],
        credentials=[Finding(
            category="credential", path="/etc/new.conf", type="hardcoded-secret",
            detail="new secret", severity="high", extra={"key": "fresh"},
        )],
    )
    diff = compute_diff(baseline, current)
    md = render_diff(diff, "md")
    assert md.startswith("# Firmware Upgrade Diff")
    assert "Added" in md
    assert "Removed (resolved)" in md
    assert "/etc/new.conf" in md
    assert "/etc/old.conf" in md


def test_render_diff_unknown_format():
    diff = compute_diff({"firmware": "x"}, Report(firmware="y", checks=[]))
    with pytest.raises(ValueError):
        render_diff(diff, "xml")


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #


def test_cli_baseline_missing_file_returns_4(sample_firmware, tmp_path):
    from embalmer.cli import main

    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--baseline", str(tmp_path / "does-not-exist.json"),
    ])
    assert rc == 4


def test_cli_baseline_emits_diff(sample_firmware, tmp_path, capsys, monkeypatch):
    from embalmer import extract
    from embalmer.cli import main

    # Plant a minimal extracted tree (one credential) without unblob.
    def _plant(fw, wd):
        base = wd / "sample-firmware.bin_extract"
        (base / "etc").mkdir(parents=True)
        (base / "etc" / "sample.conf").write_text(
            "admin_password=SuperSecret123\n"
        )

    monkeypatch.setattr(extract, "_run_unblob", _plant)

    # Baseline: an empty credentials scan, so the planted secret is an *add*.
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps({
        "firmware": "v1.bin", "checks": ["creds"], "credentials": [],
    }))

    rc = main([
        "--firmware", str(sample_firmware),
        "--workdir", str(tmp_path / "w"),
        "--checks", "creds",
        "--baseline", str(baseline_path),
        "--format", "json",
    ])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert "diff" in parsed
    assert parsed["diff"]["baseline_firmware"] == "v1.bin"
    creds = parsed["diff"]["findings"]["credentials"]
    assert creds["counts"]["added"] >= 1
