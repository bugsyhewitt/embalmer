"""Unit tests for the SPDX relationship-graph structural validation.

embalmer generates an SPDX 2.3 document from its package inventory; this module
validates that the generated document is an internally-consistent relationship
graph — the structural companion to the NTIA content check. It checks six
invariants strict SPDX validators enforce: the reserved document identifier,
SPDXID uniqueness and well-formedness, that every relationship endpoint resolves
to a declared element, that the document DESCRIBES a root, and that no package is
orphaned (declared-but-unreachable from the root).

These tests exercise:

  * :func:`spdx_validate.validate_document` — each check, passing and failing,
    against hand-built SPDX documents;
  * :func:`spdx_validate.validate` — validating a real embalmer-generated
    document built from an ``Sbom`` (which must always pass);
  * the report ``to_dict`` / markdown wiring under ``sbom.spdx_validation``;
  * the pipeline and CLI flag wiring (Article IX: the real pipeline and a real
    planted package database over mocks where practical).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from embalmer import extract, sbom, spdx_validate
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


# --- happy path: a real generated document is valid ------------------------


def test_generated_document_is_valid():
    report = spdx_validate.validate(_good_sbom(), "router.bin")
    assert report.valid is True
    assert report.failures == []
    assert report.passed_count == len(spdx_validate.ALL_CHECKS)


def test_all_six_checks_present():
    report = spdx_validate.validate(_good_sbom(), "router.bin")
    assert len(report.checks) == 6
    assert {c.check for c in report.checks} == set(spdx_validate.ALL_CHECKS)


def test_empty_inventory_still_valid():
    # No packages: only the synthetic firmware root and DESCRIBES edge — still a
    # well-formed graph.
    report = spdx_validate.validate(_sbom(), "router.bin")
    assert report.valid is True
    # The firmware root package is reachable, no component packages to orphan.
    by_check = {c.check: c for c in report.checks}
    assert by_check[spdx_validate.NO_ORPHAN_PACKAGES].passed is True


def test_package_and_relationship_counts():
    report = spdx_validate.validate(_good_sbom(), "router.bin")
    # firmware root + 2 components.
    assert report.package_count == 3
    # DESCRIBES(root) + CONTAINS x2.
    assert report.relationship_count == 3


# --- per-check failure injection -------------------------------------------


def _doc() -> dict:
    return _good_sbom().to_spdx("router.bin")


def test_document_identifier_failure():
    doc = _doc()
    doc["SPDXID"] = "SPDXRef-WrongRoot"
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.DOCUMENT_IDENTIFIER].passed is False
    assert report.valid is False
    assert "Document identifier" in report.failures


def test_duplicate_spdxid_failure():
    doc = _doc()
    # Force two packages to share an SPDXID.
    doc["packages"][1]["SPDXID"] = doc["packages"][0]["SPDXID"]
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.SPDXID_UNIQUE].passed is False
    assert by[spdx_validate.SPDXID_UNIQUE].offenders
    assert report.valid is False


def test_malformed_spdxid_failure():
    doc = _doc()
    doc["packages"][1]["SPDXID"] = "Package-no-prefix"  # missing SPDXRef-
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.SPDXID_WELL_FORMED].passed is False
    assert "Package-no-prefix" in " ".join(
        by[spdx_validate.SPDXID_WELL_FORMED].offenders
    )


def test_malformed_spdxid_disallowed_char():
    doc = _doc()
    doc["packages"][0]["SPDXID"] = "SPDXRef-bad/slash"
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.SPDXID_WELL_FORMED].passed is False


def test_dangling_relationship_endpoint_failure():
    doc = _doc()
    # Point a CONTAINS relationship at a package that does not exist.
    doc["relationships"][1]["relatedSpdxElement"] = "SPDXRef-Ghost"
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    rel = by[spdx_validate.RELATIONSHIP_ENDPOINTS]
    assert rel.passed is False
    assert "SPDXRef-Ghost" in rel.offenders
    assert report.valid is False


def test_dangling_source_endpoint_failure():
    doc = _doc()
    doc["relationships"][1]["spdxElementId"] = "SPDXRef-Nowhere"
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.RELATIONSHIP_ENDPOINTS].passed is False


def test_missing_describes_root_failure():
    doc = _doc()
    # Drop the DESCRIBES relationship entirely.
    doc["relationships"] = [
        r
        for r in doc["relationships"]
        if r.get("relationshipType") != "DESCRIBES"
    ]
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.DESCRIBES_ROOT].passed is False
    assert report.valid is False


def test_described_by_inverse_accepted():
    doc = _doc()
    # Replace DESCRIBES(doc->root) with the inverse DESCRIBED_BY(root->doc).
    for rel in doc["relationships"]:
        if rel.get("relationshipType") == "DESCRIBES":
            root = rel["relatedSpdxElement"]
            rel["relationshipType"] = "DESCRIBED_BY"
            rel["spdxElementId"] = root
            rel["relatedSpdxElement"] = spdx_validate.DOCUMENT_ID
            break
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.DESCRIBES_ROOT].passed is True


def test_orphaned_package_failure():
    doc = _doc()
    # Add a package with no relationship tying it into the graph.
    doc["packages"].append(
        {
            "SPDXID": "SPDXRef-Package-orphan",
            "name": "orphan",
            "versionInfo": "1.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "supplier": "NOASSERTION",
        }
    )
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    orphan = by[spdx_validate.NO_ORPHAN_PACKAGES]
    assert orphan.passed is False
    assert "SPDXRef-Package-orphan" in orphan.offenders
    assert report.valid is False


def test_orphan_via_severed_relationship():
    doc = _doc()
    # Remove the CONTAINS edge to the first component: it becomes unreachable.
    severed = doc["packages"][1]["SPDXID"]
    doc["relationships"] = [
        r for r in doc["relationships"] if r.get("relatedSpdxElement") != severed
    ]
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert by[spdx_validate.NO_ORPHAN_PACKAGES].passed is False
    assert severed in by[spdx_validate.NO_ORPHAN_PACKAGES].offenders


def test_multiple_failures_all_reported():
    doc = _doc()
    doc["SPDXID"] = "SPDXRef-Wrong"
    doc["packages"][0]["SPDXID"] = "bad/id"
    report = spdx_validate.validate_document(doc)
    assert report.valid is False
    assert len(report.failures) >= 2


def test_validate_document_does_not_mutate_input():
    doc = _doc()
    snapshot = copy.deepcopy(doc)
    spdx_validate.validate_document(doc)
    assert doc == snapshot


# --- serialization ---------------------------------------------------------


def test_to_dict_shape():
    report = spdx_validate.validate(_good_sbom(), "router.bin")
    d = report.to_dict()
    assert d["standard"].startswith("SPDX 2.3")
    assert d["valid"] is True
    assert d["checks_total"] == 6
    assert d["checks_passed"] == 6
    assert d["failed_checks"] == []
    assert d["package_count"] == 3
    assert d["relationship_count"] == 3
    assert len(d["checks"]) == 6


def test_to_dict_is_json_serializable():
    doc = _doc()
    doc["relationships"][1]["relatedSpdxElement"] = "SPDXRef-Ghost"
    report = spdx_validate.validate_document(doc)
    text = json.dumps(report.to_dict())
    assert "SPDXRef-Ghost" in text


def test_check_result_omits_offenders_when_passing():
    report = spdx_validate.validate(_good_sbom(), "router.bin")
    for c in report.checks:
        assert "offenders" not in c.to_dict()


def test_check_result_includes_offenders_when_failing():
    doc = _doc()
    doc["packages"][1]["SPDXID"] = doc["packages"][0]["SPDXID"]
    report = spdx_validate.validate_document(doc)
    by = {c.check: c for c in report.checks}
    assert "offenders" in by[spdx_validate.SPDXID_UNIQUE].to_dict()


# --- Report integration ----------------------------------------------------


def test_report_omits_spdx_validation_by_default():
    s = _good_sbom()
    out = Report(firmware="router.bin", checks=["sbom"], sbom=s).to_dict()
    assert "spdx_validation" not in out["sbom"]


def test_report_emits_spdx_validation_under_sbom_key():
    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.spdx_validation = spdx_validate.validate(s, "router.bin")
    out = report.to_dict()
    assert "spdx_validation" in out["sbom"]
    assert out["sbom"]["spdx_validation"]["valid"] is True
    # The BOM document still rides alongside the validation report.
    assert "bom" in out["sbom"]


def test_markdown_renders_spdx_validation_section():
    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.spdx_validation = spdx_validate.validate(s, "router.bin")
    md = report_mod.to_markdown(report)
    assert "SPDX relationship-graph validation" in md
    assert "VALID" in md


def test_markdown_renders_invalid_verdict():
    s = _good_sbom()
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    doc = s.to_spdx("router.bin")
    doc["SPDXID"] = "SPDXRef-Wrong"
    report.spdx_validation = spdx_validate.validate_document(doc)
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


def test_pipeline_spdx_validation_off_by_default(fake_extracted_tree, monkeypatch):
    from embalmer import pipeline

    base = fake_extracted_tree / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    monkeypatch.setattr(
        extract, "extract", lambda *a, **k: _fake_extraction(fake_extracted_tree)
    )
    report = pipeline.run(
        firmware="fw.bin", workdir="x", checks="sbom", enrich=False
    )
    assert report.spdx_validation is None


def test_pipeline_spdx_validation_attaches_valid_report(
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
        spdx_validate_check=True,
        enrich=False,
    )
    assert report.spdx_validation is not None
    # A real generated document is structurally valid.
    assert report.spdx_validation.valid is True
    assert report.spdx_validation.package_count >= 3  # firmware + busybox + openssl


def test_pipeline_spdx_validation_noop_without_sbom(
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
        spdx_validate_check=True,
        enrich=False,
    )
    assert report.spdx_validation is None


# --- CLI integration -------------------------------------------------------


def _plant_dpkg_tree(workdir):
    base = Path(workdir) / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)


@pytest.fixture
def _mock_extract(monkeypatch):
    monkeypatch.setattr(extract, "_run_unblob", lambda fw, wd: _plant_dpkg_tree(wd))


def test_cli_sbom_validate_spdx_json(sample_firmware, tmp_path, capsys, _mock_extract):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-validate-spdx",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    sv = data["sbom"]["spdx_validation"]
    assert sv["checks_total"] == 6
    assert sv["valid"] is True
    assert sv["failed_checks"] == []


def test_cli_without_flag_omits_spdx_validation(
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
    assert "spdx_validation" not in data["sbom"]


def test_cli_validate_spdx_in_markdown(
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
            "--sbom-validate-spdx",
            "--format",
            "md",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "SPDX relationship-graph validation" in out
