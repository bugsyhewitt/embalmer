"""Tests for VEX-override: import a CycloneDX VEX and apply to scan results.

The override module reads a CycloneDX 1.6 VEX JSON document, distills each
``vulnerabilities[].analysis.state`` into a :class:`VexAssertion`, and applies
those assertions to an :class:`embalmer.sbom_cve.SbomCveReport` in place —
suppressing the CVE matches whose state is one of ``not_affected`` /
``false_positive`` / ``resolved`` / ``resolved_with_pedigree`` / ``fixed`` and
annotating the rest with the vendor's assertion.

These tests exercise:

* the document loader (file errors, JSON errors, layout permutations, multiple
  ``affects[].ref`` expansion, missing/unknown state handling);
* the apply pass (unscoped vs purl-scoped, suppress vs annotate, orphans,
  match-order stability, no double-suppression);
* end-to-end through the CLI: a VEX file suppresses a CVE that would otherwise
  trip ``--fail-on`` so the gate exits 0 instead of 10, and the audit trail
  rides under ``sbom.vex_override`` in the JSON report.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from embalmer import sbom_cve, vex_override
from embalmer.cli import main as cli_main
from embalmer.models import Report
from embalmer.sbom import Component, Sbom
from embalmer.sbom_cve import CveMatch, SbomCveReport
from embalmer.severity import _reset_kev_cache
from embalmer.vex_override import (
    SUPPRESSING_STATES,
    VexAssertion,
    VexOverrideError,
    VexOverrideReport,
    apply,
    load,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _match(cve_id: str, purl: str, severity: str = "high", cvss: float = 7.5,
           in_kev: bool = False) -> CveMatch:
    return CveMatch(
        cve_id=cve_id, purl=purl, cvss=cvss, severity=severity, in_kev=in_kev
    )


def _vex_doc(*entries: dict) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "vulnerabilities": list(entries),
    }


def _vex_entry(cve_id: str, state: str, *, purl: str | None = None,
               justification: str | None = None, response: list | None = None,
               detail: str | None = None) -> dict:
    analysis: dict = {"state": state}
    if justification is not None:
        analysis["justification"] = justification
    if response is not None:
        analysis["response"] = response
    if detail is not None:
        analysis["detail"] = detail
    entry: dict = {"id": cve_id, "analysis": analysis}
    if purl is not None:
        entry["affects"] = [{"ref": purl}]
    return entry


def _write(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# load(): parse a VEX document
# ---------------------------------------------------------------------------


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(VexOverrideError, match="could not read"):
        load(tmp_path / "does-not-exist.json")


def test_load_invalid_json_raises(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(VexOverrideError, match="not valid JSON"):
        load(p)


def test_load_no_vulnerabilities_array_raises(tmp_path):
    p = _write(tmp_path / "v.json", {"bomFormat": "CycloneDX"})
    with pytest.raises(VexOverrideError, match="no `vulnerabilities` array"):
        load(p)


def test_load_top_level_vulnerabilities(tmp_path):
    doc = _vex_doc(
        _vex_entry("CVE-2014-0160", "not_affected",
                   justification="code_not_present"),
    )
    p = _write(tmp_path / "v.json", doc)
    assertions = load(p)
    assert len(assertions) == 1
    a = assertions[0]
    assert a.cve_id == "CVE-2014-0160"
    assert a.state == "not_affected"
    assert a.justification == "code_not_present"
    assert a.purl is None
    assert a.suppresses is True


def test_load_nested_under_vex_key(tmp_path):
    # embalmer emits VEX under `vex.bom.vulnerabilities`; the loader must
    # accept the same shape it produces so a round-trip works.
    doc = {"vex": {"bom": _vex_doc(_vex_entry("CVE-2020-0001", "resolved"))}}
    p = _write(tmp_path / "v.json", doc)
    a = load(p)
    assert len(a) == 1
    assert a[0].cve_id == "CVE-2020-0001"
    assert a[0].state == "resolved"


def test_load_nested_under_bom_key(tmp_path):
    doc = {"bom": _vex_doc(_vex_entry("CVE-2021-1", "exploitable"))}
    p = _write(tmp_path / "v.json", doc)
    a = load(p)
    assert len(a) == 1 and a[0].state == "exploitable"
    assert a[0].suppresses is False


def test_load_multiple_affects_refs_expand_to_one_assertion_each(tmp_path):
    # The CycloneDX `affects` is a list; one entry asserting state for two
    # purls expands to two scoped assertions, so the apply pass can address
    # each (cve_id, purl) pair symmetrically.
    entry = _vex_entry("CVE-2014-0160", "not_affected")
    entry["affects"] = [
        {"ref": "pkg:deb/debian/openssl@1.0.1f"},
        {"ref": "pkg:generic/openssl@1.0.1f"},
    ]
    p = _write(tmp_path / "v.json", _vex_doc(entry))
    assertions = load(p)
    assert len(assertions) == 2
    purls = {a.purl for a in assertions}
    assert purls == {
        "pkg:deb/debian/openssl@1.0.1f",
        "pkg:generic/openssl@1.0.1f",
    }


def test_load_skips_entries_without_state(tmp_path):
    doc = _vex_doc(
        _vex_entry("CVE-1", "resolved"),
        # No analysis at all: dropped.
        {"id": "CVE-2"},
        # Analysis but no state: dropped.
        {"id": "CVE-3", "analysis": {"justification": "x"}},
        # No id: dropped.
        {"analysis": {"state": "resolved"}},
    )
    p = _write(tmp_path / "v.json", doc)
    a = load(p)
    assert [x.cve_id for x in a] == ["CVE-1"]


def test_load_unknown_state_kept_but_does_not_suppress(tmp_path):
    # An unknown state must be recorded verbatim (the operator may have used a
    # newer CycloneDX vocabulary) but the conservative posture is to NOT
    # suppress on a state embalmer does not recognize.
    p = _write(
        tmp_path / "v.json", _vex_doc(_vex_entry("CVE-X", "speculative"))
    )
    a = load(p)
    assert len(a) == 1
    assert a[0].state == "speculative"
    assert a[0].suppresses is False


def test_load_carries_response_array(tmp_path):
    entry = _vex_entry(
        "CVE-1", "exploitable", response=["will_not_fix", "update"]
    )
    p = _write(tmp_path / "v.json", _vex_doc(entry))
    a = load(p)
    assert a[0].response == ("will_not_fix", "update")


# ---------------------------------------------------------------------------
# apply(): mutate the SbomCveReport in place
# ---------------------------------------------------------------------------


def test_apply_unscoped_suppresses_every_match_of_cve():
    report = SbomCveReport(matches=[
        _match("CVE-1", "pkg:deb/openssl@1.0"),
        _match("CVE-1", "pkg:generic/openssl@1.0"),
        _match("CVE-2", "pkg:deb/curl@7.0"),
    ])
    assertions = [VexAssertion(cve_id="CVE-1", state="not_affected")]
    ov = apply(report, assertions, source="vendor.json")
    assert [m.cve_id for m in report.matches] == ["CVE-2"]
    assert ov.suppressed_count == 2
    assert ov.annotated_count == 0
    assert all(s["cve_id"] == "CVE-1" for s in ov.suppressed)


def test_apply_purl_scope_only_suppresses_matching_purl():
    report = SbomCveReport(matches=[
        _match("CVE-1", "pkg:deb/openssl@1.0"),
        _match("CVE-1", "pkg:generic/openssl@1.0"),
    ])
    assertions = [
        VexAssertion(
            cve_id="CVE-1",
            state="not_affected",
            purl="pkg:deb/openssl@1.0",
        )
    ]
    ov = apply(report, assertions, source="vendor.json")
    assert [m.purl for m in report.matches] == ["pkg:generic/openssl@1.0"]
    assert ov.suppressed_count == 1
    # The unscoped purl was not addressed at all — no annotation either.
    assert ov.annotated_count == 0


def test_apply_exploitable_state_annotates_does_not_suppress():
    report = SbomCveReport(matches=[
        _match("CVE-1", "pkg:deb/openssl@1.0", severity="critical", in_kev=True),
    ])
    assertions = [VexAssertion(
        cve_id="CVE-1",
        state="exploitable",
        justification="confirmed_in_production",
    )]
    ov = apply(report, assertions, source="v.json")
    assert len(report.matches) == 1, "exploitable must keep the match"
    assert ov.suppressed_count == 0
    assert ov.annotated_count == 1
    assert ov.annotated[0]["vex"]["state"] == "exploitable"


def test_apply_in_triage_annotates():
    report = SbomCveReport(matches=[_match("CVE-1", "pkg:x/y@1.0")])
    assertions = [VexAssertion(cve_id="CVE-1", state="in_triage")]
    ov = apply(report, assertions, source="v.json")
    assert len(report.matches) == 1
    assert ov.annotated_count == 1


def test_apply_orphan_assertion_recorded():
    # Vendor VEX asserts a CVE the scan never matched: the assertion must be
    # surfaced as an orphan so a stale VEX does not silently lose signal.
    report = SbomCveReport(matches=[_match("CVE-1", "pkg:x/y@1.0")])
    assertions = [VexAssertion(cve_id="CVE-999", state="not_affected")]
    ov = apply(report, assertions, source="v.json")
    assert len(report.matches) == 1
    assert ov.suppressed_count == 0
    assert len(ov.orphans) == 1
    assert ov.orphans[0].cve_id == "CVE-999"


def test_apply_orphan_when_scope_does_not_match():
    report = SbomCveReport(matches=[_match("CVE-1", "pkg:x/y@1.0")])
    assertions = [VexAssertion(
        cve_id="CVE-1", state="not_affected", purl="pkg:other/z@1.0"
    )]
    ov = apply(report, assertions, source="v.json")
    assert len(report.matches) == 1
    assert len(ov.orphans) == 1


def test_apply_preserves_remaining_match_order():
    report = SbomCveReport(matches=[
        _match("CVE-A", "pkg:p/a@1"),
        _match("CVE-B", "pkg:p/b@1"),
        _match("CVE-C", "pkg:p/c@1"),
    ])
    assertions = [VexAssertion(cve_id="CVE-B", state="resolved")]
    apply(report, assertions, source="v.json")
    assert [m.cve_id for m in report.matches] == ["CVE-A", "CVE-C"]


def test_apply_does_not_double_suppress_with_two_assertions_on_same_match():
    report = SbomCveReport(matches=[_match("CVE-1", "pkg:x/y@1.0")])
    assertions = [
        VexAssertion(cve_id="CVE-1", state="not_affected"),
        VexAssertion(cve_id="CVE-1", state="resolved"),
    ]
    ov = apply(report, assertions, source="v.json")
    assert len(report.matches) == 0
    assert ov.suppressed_count == 1
    # The second assertion finds the match already drained — recorded as an orphan.
    assert len(ov.orphans) == 1


def test_suppressing_states_set_is_what_we_documented():
    # Lock the suppression vocabulary so a future edit does not silently
    # change CI behavior for a vendor that relies on a specific state.
    assert SUPPRESSING_STATES == {
        "not_affected",
        "false_positive",
        "resolved",
        "resolved_with_pedigree",
        "fixed",
    }


# ---------------------------------------------------------------------------
# Report shape
# ---------------------------------------------------------------------------


def test_assertion_to_dict_omits_empty_optional_fields():
    a = VexAssertion(cve_id="CVE-1", state="not_affected")
    d = a.to_dict()
    assert d == {"cve_id": "CVE-1", "state": "not_affected", "suppresses": True}


def test_assertion_to_dict_carries_full_audit():
    a = VexAssertion(
        cve_id="CVE-1",
        state="not_affected",
        purl="pkg:x/y@1.0",
        justification="code_not_present",
        response=("will_not_fix",),
        detail="The vulnerable function is dead-stripped at link time.",
    )
    d = a.to_dict()
    assert d["purl"] == "pkg:x/y@1.0"
    assert d["justification"] == "code_not_present"
    assert d["response"] == ["will_not_fix"]
    assert d["detail"].startswith("The vulnerable function")


def test_override_report_to_dict_shape():
    rep = VexOverrideReport(
        source="v.json",
        assertions=[VexAssertion(cve_id="CVE-1", state="not_affected")],
        suppressed=[{"cve_id": "CVE-1", "purl": "pkg:x@1", "vex": {}}],
        annotated=[],
        orphans=[VexAssertion(cve_id="CVE-9", state="resolved")],
    )
    d = rep.to_dict()
    assert d["source"] == "v.json"
    assert d["assertion_count"] == 1
    assert d["suppressed_count"] == 1
    assert d["annotated_count"] == 0
    assert d["orphan_count"] == 1
    assert d["suppressed"] == [{"cve_id": "CVE-1", "purl": "pkg:x@1", "vex": {}}]


# ---------------------------------------------------------------------------
# End-to-end: VEX suppresses a CVE so --fail-on does not trigger
# ---------------------------------------------------------------------------


def _ext_root(tmp_path: Path) -> Path:
    """A minimal extraction-root tree the pipeline accepts."""
    root = tmp_path / "ext"
    root.mkdir()
    (root / "usr").mkdir()
    return root


def test_cli_vex_override_suppresses_cve_and_gate_does_not_trigger(
    tmp_path, capsys, monkeypatch
):
    """End-to-end: a VEX `not_affected` removes a critical CVE from the gate.

    Builds an in-memory pipeline state where ``--sbom-cve`` finds a critical CVE
    on the OpenSSL component, then proves the same scan + ``--vex-override``
    + ``--fail-on high`` exits 0 (gate did not trigger) because the VEX
    suppressed the match before the gate scored it.
    """
    _reset_kev_cache()

    # Stand up a real Report with one CVE match the gate would otherwise trip on.
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00")
    extraction_root = _ext_root(tmp_path)

    openssl = Component(
        name="openssl",
        version="1.0.1f",
        source="binary",
        db_path="usr/lib/libcrypto.so",
        cpe="cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        supplier="openssl",
    )
    sbom_obj = Sbom(components=[openssl])
    cve_match = _match(
        "CVE-2014-0160",
        openssl.purl(),
        severity="critical",
        cvss=9.8,
        in_kev=True,
    )
    cve_report = SbomCveReport(matches=[cve_match], components_checked=1)

    from embalmer import extract
    from embalmer.models import ExtractionResult

    def _fake_extract(firmware, workdir, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=0,
            extraction_time_ms=0,
            extract_root=str(extraction_root),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract, "extract", _fake_extract)
    # Stub the scanner-heavy modules so the pipeline runs without unblob/blight.
    from embalmer import binaries, certs, components, creds, sbom as sbom_mod
    monkeypatch.setattr(creds, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(certs, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(binaries, "analyze", lambda *_a, **_k: [])
    monkeypatch.setattr(components, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(sbom_mod, "scan", lambda *_a, **_k: sbom_obj)
    monkeypatch.setattr(
        sbom_cve, "cross_reference",
        lambda sbom, **_kw: SbomCveReport(
            matches=[cve_match], components_checked=1
        ),
    )

    vex_path = _write(
        tmp_path / "vendor.vex.json",
        _vex_doc(_vex_entry(
            "CVE-2014-0160", "not_affected",
            justification="code_not_present",
            detail="The vulnerable heartbeat path is compiled out.",
        )),
    )

    out_path = tmp_path / "report.json"
    rc = cli_main([
        "--firmware", str(firmware),
        "--workdir", str(tmp_path / "wd"),
        "--checks", "sbom",
        "--sbom-cve",
        "--vex-override", str(vex_path),
        "--fail-on", "high",
        "--output", str(out_path),
    ])
    assert rc == 0, "gate must NOT trigger when VEX suppressed the only critical CVE"

    report_data = json.loads(out_path.read_text(encoding="utf-8"))
    ov = report_data["sbom"]["vex_override"]
    assert ov["suppressed_count"] == 1
    assert ov["suppressed"][0]["cve_id"] == "CVE-2014-0160"
    assert ov["suppressed"][0]["vex"]["state"] == "not_affected"
    # And the gate's scan-side CVE list is now empty (the match was filtered).
    assert report_data["sbom"]["vulnerabilities"]["cve_count"] == 0


def test_cli_vex_override_without_match_records_orphan(tmp_path, monkeypatch):
    """A VEX asserting a CVE not in the scan is surfaced as an orphan."""
    _reset_kev_cache()
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00")
    extraction_root = _ext_root(tmp_path)

    sbom_obj = Sbom(components=[])
    from embalmer import extract
    from embalmer.models import ExtractionResult

    monkeypatch.setattr(
        extract, "extract",
        lambda *_a, **_k: ExtractionResult(
            extraction_tree={}, file_count=0, extraction_time_ms=0,
            extract_root=str(extraction_root), extractor_used="unblob",
        ),
    )
    from embalmer import binaries, certs, components, creds, sbom as sbom_mod
    monkeypatch.setattr(creds, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(certs, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(binaries, "analyze", lambda *_a, **_k: [])
    monkeypatch.setattr(components, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(sbom_mod, "scan", lambda *_a, **_k: sbom_obj)
    monkeypatch.setattr(
        sbom_cve, "cross_reference",
        lambda sbom, **_kw: SbomCveReport(matches=[], components_checked=0),
    )

    vex_path = _write(
        tmp_path / "vendor.vex.json",
        _vex_doc(_vex_entry("CVE-1999-0001", "resolved")),
    )

    out_path = tmp_path / "report.json"
    rc = cli_main([
        "--firmware", str(firmware),
        "--workdir", str(tmp_path / "wd"),
        "--checks", "sbom",
        "--sbom-cve",
        "--vex-override", str(vex_path),
        "--output", str(out_path),
    ])
    assert rc == 0
    data = json.loads(out_path.read_text(encoding="utf-8"))
    ov = data["sbom"]["vex_override"]
    assert ov["suppressed_count"] == 0
    assert ov["orphan_count"] == 1


def test_cli_vex_override_bad_file_returns_usage_error(tmp_path):
    """A malformed VEX file is a usage error (exit 1) with a clear message."""
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    rc = cli_main([
        "--firmware", str(firmware),
        "--checks", "sbom",
        "--sbom-cve",
        "--vex-override", str(bad),
    ])
    assert rc == 1


def test_cli_vex_override_without_sbom_cve_is_noop(tmp_path, monkeypatch):
    """No --sbom-cve / --sbom-osv means no matches to override — silent no-op.

    The override only attaches when there is a CVE list to score. This mirrors
    the posture every other SBOM gate takes (no inventory, no verdict).
    """
    _reset_kev_cache()
    firmware = tmp_path / "fw.bin"
    firmware.write_bytes(b"\x00")
    extraction_root = _ext_root(tmp_path)

    from embalmer import extract
    from embalmer.models import ExtractionResult

    monkeypatch.setattr(
        extract, "extract",
        lambda *_a, **_k: ExtractionResult(
            extraction_tree={}, file_count=0, extraction_time_ms=0,
            extract_root=str(extraction_root), extractor_used="unblob",
        ),
    )
    from embalmer import binaries, certs, components, creds, sbom as sbom_mod
    monkeypatch.setattr(creds, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(certs, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(binaries, "analyze", lambda *_a, **_k: [])
    monkeypatch.setattr(components, "scan", lambda *_a, **_k: [])
    monkeypatch.setattr(sbom_mod, "scan", lambda *_a, **_k: Sbom(components=[]))

    vex_path = _write(
        tmp_path / "v.json", _vex_doc(_vex_entry("CVE-1", "resolved"))
    )
    out_path = tmp_path / "r.json"
    rc = cli_main([
        "--firmware", str(firmware),
        "--workdir", str(tmp_path / "wd"),
        "--checks", "sbom",
        "--vex-override", str(vex_path),
        "--output", str(out_path),
    ])
    assert rc == 0
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "vex_override" not in data.get("sbom", {})
