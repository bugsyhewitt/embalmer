"""Unit tests for the CycloneDX component purl (Package URL) validation.

embalmer generates a CycloneDX 1.6 BOM from its package inventory; this module
validates that every component's purl conforms to the package-url specification
— the CycloneDX-side companion to the SPDX relationship-graph validation. The
purl is the identifier downstream vuln scanners join on, so a malformed one
makes a component silently un-matchable. It checks six invariants the spec makes
mandatory: the ``pkg:`` scheme, a valid lowercase embalmer-emitted type, a
present name and version, correctly percent-encoded segments, and well-formed
qualifiers.

These tests exercise:

  * :func:`purl_validate.validate_purls` / :func:`validate_document` — each
    check, passing and failing, against hand-built purls and BOM documents;
  * :func:`purl_validate.validate` — validating a real embalmer-generated BOM
    built from an ``Sbom`` (which must always pass);
  * the report ``to_dict`` / markdown wiring under ``sbom.purl_validation``;
  * the pipeline and CLI flag wiring (Article IX: the real pipeline and a real
    planted package database over mocks where practical).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from embalmer import extract, purl_validate, sbom
from embalmer import report as report_mod
from embalmer.cli import main as cli_main
from embalmer.models import Report


# --- fixtures --------------------------------------------------------------

_DPKG_STATUS = """\
Package: busybox
Status: install ok installed
Architecture: amd64
Version: 1.35.0-4
Description: Tiny utilities for small and embedded systems

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _sbom(*components: sbom.Component) -> sbom.Sbom:
    return sbom.Sbom(components=list(components))


def _good_sbom() -> sbom.Sbom:
    return _sbom(
        sbom.Component(name="busybox", version="1.35", source="dpkg"),
        sbom.Component(name="openssl", version="3.0", source="apk"),
    )


# --- happy path: a real generated BOM is valid -----------------------------


def test_generated_bom_is_valid():
    report = purl_validate.validate(_good_sbom(), "router.bin")
    assert report.valid is True
    assert report.failures == []
    assert report.passed_count == len(purl_validate.ALL_CHECKS)


def test_all_six_checks_present():
    report = purl_validate.validate(_good_sbom(), "router.bin")
    assert len(report.checks) == 6
    assert {c.check for c in report.checks} == set(purl_validate.ALL_CHECKS)


def test_empty_inventory_is_vacuously_valid():
    report = purl_validate.validate(_sbom(), "router.bin")
    assert report.valid is True
    assert report.component_count == 0


def test_component_count():
    report = purl_validate.validate(_good_sbom(), "router.bin")
    assert report.component_count == 2


def test_each_purl_type_passes():
    # Every type embalmer maps must validate.
    s = _sbom(
        sbom.Component(name="a", version="1", source="dpkg"),  # -> deb
        sbom.Component(name="b", version="1", source="opkg"),  # -> opkg
        sbom.Component(name="c", version="1", source="apk"),  # -> apk
        sbom.Component(name="d", version="1", source="binary"),  # -> generic
    )
    report = purl_validate.validate(s, "router.bin")
    assert report.valid is True


def test_arch_qualifier_passes():
    # A component with an architecture emits ``?arch=...`` — must validate.
    s = _sbom(
        sbom.Component(
            name="busybox", version="1.35", source="dpkg", architecture="amd64"
        )
    )
    report = purl_validate.validate(s, "router.bin")
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.QUALIFIERS_VALID].passed is True
    assert report.valid is True


def test_special_chars_in_name_passes():
    # A name with a character that must be percent-encoded; the generator encodes
    # it, so the encoding check passes.
    s = _sbom(sbom.Component(name="lib c++", version="1.0", source="dpkg"))
    report = purl_validate.validate(s, "router.bin")
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.ENCODING_VALID].passed is True
    assert report.valid is True


# --- per-check failure injection (raw purl strings) ------------------------


def test_scheme_failure():
    report = purl_validate.validate_purls(["deb/busybox@1.35"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.SCHEME_PREFIX].passed is False
    assert "deb/busybox@1.35" in by[purl_validate.SCHEME_PREFIX].offenders
    assert report.valid is False
    assert "purl scheme prefix" in report.failures


def test_invalid_type_syntax_failure():
    # A type starting with a digit violates the spec rule.
    report = purl_validate.validate_purls(["pkg:9deb/busybox@1.35"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.TYPE_VALID].passed is False
    assert report.valid is False


def test_uppercase_type_failure():
    # The spec requires a lowercased type.
    report = purl_validate.validate_purls(["pkg:DEB/busybox@1.35"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.TYPE_VALID].passed is False


def test_unknown_type_failure():
    # Syntactically valid but not a type embalmer emits.
    report = purl_validate.validate_purls(["pkg:npm/leftpad@1.0"])
    by = {c.check: c for c in report.checks}
    tv = by[purl_validate.TYPE_VALID]
    assert tv.passed is False
    assert any("npm" in o for o in tv.offenders)


def test_missing_name_failure():
    report = purl_validate.validate_purls(["pkg:deb/@1.35"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.NAME_PRESENT].passed is False
    assert report.valid is False


def test_no_path_separator_is_missing_name():
    # No '/', so the whole tail is the type and the name is empty.
    report = purl_validate.validate_purls(["pkg:deb"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.NAME_PRESENT].passed is False


def test_missing_version_failure():
    report = purl_validate.validate_purls(["pkg:deb/busybox"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.VERSION_PRESENT].passed is False
    assert report.valid is False
    assert "purl version present" in report.failures


def test_empty_version_after_at_failure():
    report = purl_validate.validate_purls(["pkg:deb/busybox@"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.VERSION_PRESENT].passed is False


def test_unencoded_space_in_name_failure():
    # A raw space in the name segment is not canonically encoded.
    report = purl_validate.validate_purls(["pkg:deb/lib c@1.0"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.ENCODING_VALID].passed is False
    assert report.valid is False


def test_unencoded_special_in_version_failure():
    report = purl_validate.validate_purls(["pkg:deb/busybox@1 2"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.ENCODING_VALID].passed is False


def test_qualifier_no_value_failure():
    report = purl_validate.validate_purls(["pkg:deb/busybox@1.35?arch"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.QUALIFIERS_VALID].passed is False
    assert report.valid is False


def test_qualifier_empty_value_failure():
    report = purl_validate.validate_purls(["pkg:deb/busybox@1.35?arch="])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.QUALIFIERS_VALID].passed is False


def test_qualifier_uppercase_key_failure():
    report = purl_validate.validate_purls(["pkg:deb/busybox@1.35?Arch=amd64"])
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.QUALIFIERS_VALID].passed is False


def test_qualifier_repeated_key_failure():
    report = purl_validate.validate_purls(
        ["pkg:deb/busybox@1.35?arch=amd64&arch=arm64"]
    )
    by = {c.check: c for c in report.checks}
    qv = by[purl_validate.QUALIFIERS_VALID]
    assert qv.passed is False
    assert any("repeats" in o for o in qv.offenders)


def test_subpath_is_stripped_not_a_failure():
    # A subpath (#...) is valid and embalmer never emits one; it must not bleed
    # into the version or qualifier checks.
    report = purl_validate.validate_purls(["pkg:deb/busybox@1.35#some/path"])
    assert report.valid is True


def test_multiple_failures_all_reported():
    report = purl_validate.validate_purls(["deb/busybox"])  # no scheme, no version
    assert report.valid is False
    assert len(report.failures) >= 2


def test_one_bad_purl_among_good_fails_whole_report():
    report = purl_validate.validate_purls(
        ["pkg:deb/busybox@1.35", "pkg:deb/openssl"]  # second has no version
    )
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.VERSION_PRESENT].passed is False
    assert "pkg:deb/openssl" in by[purl_validate.VERSION_PRESENT].offenders
    assert report.valid is False


# --- validate_document -----------------------------------------------------


def _bom() -> dict:
    return _good_sbom().to_cyclonedx("router.bin")


def test_validate_document_valid():
    report = purl_validate.validate_document(_bom())
    assert report.valid is True
    assert report.component_count == 2


def test_validate_document_missing_purl_key():
    bom = _bom()
    del bom["components"][0]["purl"]
    report = purl_validate.validate_document(bom)
    # An empty purl fails scheme/name/version.
    assert report.valid is False


def test_validate_document_does_not_mutate_input():
    bom = _bom()
    snapshot = copy.deepcopy(bom)
    purl_validate.validate_document(bom)
    assert bom == snapshot


def test_validate_document_corrupted_purl():
    bom = _bom()
    bom["components"][1]["purl"] = "pkg:deb/openssl"  # drop version
    report = purl_validate.validate_document(bom)
    by = {c.check: c for c in report.checks}
    assert by[purl_validate.VERSION_PRESENT].passed is False


# --- serialization ---------------------------------------------------------


def test_to_dict_shape():
    report = purl_validate.validate(_good_sbom(), "router.bin")
    d = report.to_dict()
    assert d["standard"].startswith("package-url")
    assert d["valid"] is True
    assert d["checks_total"] == 6
    assert d["checks_passed"] == 6
    assert d["failed_checks"] == []
    assert d["component_count"] == 2
    assert len(d["checks"]) == 6


def test_to_dict_is_json_serializable():
    report = purl_validate.validate_purls(["pkg:deb/openssl"])
    text = json.dumps(report.to_dict())
    assert "purl version present" in text


def test_check_result_omits_offenders_when_passing():
    report = purl_validate.validate(_good_sbom(), "router.bin")
    for c in report.checks:
        assert "offenders" not in c.to_dict()


def test_check_result_includes_offenders_when_failing():
    report = purl_validate.validate_purls(["pkg:deb/openssl"])
    by = {c.check: c for c in report.checks}
    assert "offenders" in by[purl_validate.VERSION_PRESENT].to_dict()


# --- Report integration ----------------------------------------------------


def test_report_omits_purl_validation_by_default():
    s = _good_sbom()
    out = Report(firmware="router.bin", checks=["sbom"], sbom=s).to_dict()
    assert "purl_validation" not in out["sbom"]


def test_report_emits_purl_validation_under_sbom_key():
    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.purl_validation = purl_validate.validate(s, "router.bin")
    out = report.to_dict()
    assert "purl_validation" in out["sbom"]
    assert out["sbom"]["purl_validation"]["valid"] is True
    # The BOM document still rides alongside the validation report.
    assert "bom" in out["sbom"]


def test_purl_validation_coexists_with_spdx_validation():
    from embalmer import spdx_validate

    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.purl_validation = purl_validate.validate(s, "router.bin")
    report.spdx_validation = spdx_validate.validate(s, "router.bin")
    out = report.to_dict()
    assert "purl_validation" in out["sbom"]
    assert "spdx_validation" in out["sbom"]


def test_markdown_renders_purl_validation_section():
    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.purl_validation = purl_validate.validate(s, "router.bin")
    md = report_mod.to_markdown(report)
    assert "CycloneDX purl validation" in md
    assert "VALID" in md


def test_markdown_renders_invalid_verdict():
    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    bom = s.to_cyclonedx("router.bin")
    bom["components"][0]["purl"] = "pkg:deb/busybox"  # drop version
    report.purl_validation = purl_validate.validate_document(bom)
    md = report_mod.to_markdown(report)
    assert "INVALID" in md
    assert "Failed:" in md


# --- pipeline integration --------------------------------------------------


def _fake_extraction(root: Path):
    from embalmer.models import ExtractionResult

    extract_root = str(root / "sample-firmware.bin_extract")
    return ExtractionResult(
        extraction_tree={},
        file_count=0,
        extraction_time_ms=0,
        extract_root=extract_root,
        extractor_used="unblob",
    )


def test_pipeline_purl_validation_off_by_default(fake_extracted_tree, monkeypatch):
    from embalmer import pipeline

    base = fake_extracted_tree / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    monkeypatch.setattr(
        extract, "extract", lambda *a, **k: _fake_extraction(fake_extracted_tree)
    )
    report = pipeline.run(
        firmware="fw.bin", workdir="x", checks="sbom", enrich=False
    )
    assert report.purl_validation is None


def test_pipeline_purl_validation_attaches_valid_report(
    fake_extracted_tree, monkeypatch
):
    from embalmer import pipeline

    base = fake_extracted_tree / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    monkeypatch.setattr(
        extract, "extract", lambda *a, **k: _fake_extraction(fake_extracted_tree)
    )
    report = pipeline.run(
        firmware="fw.bin",
        workdir="x",
        checks="sbom",
        purl_validate_check=True,
        enrich=False,
    )
    assert report.purl_validation is not None
    # A real generated BOM has spec-valid purls.
    assert report.purl_validation.valid is True
    assert report.purl_validation.component_count >= 2  # busybox + openssl


def test_pipeline_purl_validation_noop_without_sbom(
    fake_extracted_tree, monkeypatch
):
    from embalmer import pipeline

    monkeypatch.setattr(
        extract, "extract", lambda *a, **k: _fake_extraction(fake_extracted_tree)
    )
    report = pipeline.run(
        firmware="fw.bin",
        workdir="x",
        checks="creds",
        purl_validate_check=True,
        enrich=False,
    )
    assert report.purl_validation is None


# --- CLI integration -------------------------------------------------------


def _plant_dpkg_tree(workdir):
    base = Path(workdir) / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)


@pytest.fixture
def _mock_extract(monkeypatch):
    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_dpkg_tree(wd))


def test_cli_sbom_validate_purl_json(sample_firmware, tmp_path, capsys, _mock_extract):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-validate-purl",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    pv = data["sbom"]["purl_validation"]
    assert pv["checks_total"] == 6
    assert pv["valid"] is True
    assert pv["failed_checks"] == []


def test_cli_without_flag_omits_purl_validation(
    sample_firmware, tmp_path, capsys, _mock_extract
):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "purl_validation" not in data["sbom"]


def test_cli_validate_purl_in_markdown(
    sample_firmware, tmp_path, capsys, _mock_extract
):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-validate-purl",
            "--format",
            "md",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "CycloneDX purl validation" in out


def test_cli_both_validations_together(
    sample_firmware, tmp_path, capsys, _mock_extract
):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-validate-purl",
            "--sbom-validate-spdx",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["sbom"]["purl_validation"]["valid"] is True
    assert data["sbom"]["spdx_validation"]["valid"] is True
