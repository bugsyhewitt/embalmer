"""Unit tests for the NTIA SBOM minimum-elements compliance check.

The NTIA's July 2021 *Minimum Elements For an SBOM* report (the EO-14028
baseline) defines seven minimum elements every SBOM must carry. This module
scores an embalmer :class:`~embalmer.sbom.Sbom` against those elements and emits
a structured pass/fail conformance report.

These tests exercise:

  * :func:`ntia.check` — per-element scoring against a real ``Sbom`` inventory;
  * the all-or-nothing per-element rule and the empty-inventory edge case;
  * the honest Supplier Name gap (embalmer emits NOASSERTION, so a real BOM is
    reported non-compliant on exactly that element);
  * the report ``to_dict`` / markdown wiring under the ``sbom.ntia`` key;
  * the pipeline and CLI flag wiring (Article IX: the real pipeline and a real
    planted package database over mocks where practical).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from embalmer import extract, ntia, sbom
from embalmer.cli import main as cli_main
from embalmer.models import Report
from embalmer import report as report_mod


# --- realistic database fixture -------------------------------------------

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


# --- per-element scoring ---------------------------------------------------


def test_check_scores_all_seven_elements():
    report = ntia.check(_sbom(sbom.Component(name="x", version="1", source="dpkg")))
    assert len(report.elements) == 7
    labels = {e.element for e in report.elements}
    assert labels == set(ntia.ALL_ELEMENTS)


def test_component_name_version_identifier_satisfied():
    report = ntia.check(
        _sbom(
            sbom.Component(name="openssl", version="3.0", source="dpkg"),
            sbom.Component(name="busybox", version="1.36", source="apk"),
        )
    )
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.COMPONENT_NAME].satisfied
    assert by_el[ntia.COMPONENT_VERSION].satisfied
    assert by_el[ntia.UNIQUE_IDENTIFIER].satisfied


def test_document_level_elements_always_satisfied():
    # Author, Timestamp, and Dependency Relationship are stamped on every
    # generated BOM, so they pass even for an empty inventory.
    report = ntia.check(_sbom())
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.SBOM_AUTHOR].satisfied
    assert by_el[ntia.TIMESTAMP].satisfied
    assert by_el[ntia.DEPENDENCY_RELATIONSHIP].satisfied


def test_supplier_is_the_honest_gap():
    # embalmer never asserts a supplier (NOASSERTION), so Supplier Name is the
    # one per-component element that fails on a real firmware BOM.
    report = ntia.check(
        _sbom(sbom.Component(name="openssl", version="3.0", source="dpkg"))
    )
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.SUPPLIER_NAME].satisfied is False
    assert "NOASSERTION" in by_el[ntia.SUPPLIER_NAME].detail
    assert report.compliant is False
    assert "Supplier Name" in report.missing


def test_supplier_credited_when_asserted():
    # A component carrying a real supplier value satisfies the element. (The
    # Component dataclass has no supplier field today; a duck-typed attribute
    # exercises the positive branch so the check is future-proof.)
    comp = sbom.Component(name="curl", version="8.0", source="dpkg")
    comp.supplier = "Acme Corp"  # type: ignore[attr-defined]
    report = ntia.check(_sbom(comp))
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.SUPPLIER_NAME].satisfied is True
    assert report.compliant is True
    assert report.missing == []


def test_binary_components_supplier_enrichment_satisfies_element():
    # Binary-detected components carry their upstream CPE vendor as the supplier
    # (the components check sets `vendor`), so a BOM made entirely of
    # binary-detected components satisfies Supplier Name and is NTIA-compliant.
    report = ntia.check(
        _sbom(
            sbom.Component(
                name="openssl", version="1.0.1f", source="binary",
                cpe="cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
                supplier="openssl",
            ),
            sbom.Component(
                name="curl", version="7.79.1", source="binary",
                cpe="cpe:2.3:a:haxx:curl:7.79.1:*:*:*:*:*:*:*",
                supplier="haxx",
            ),
        )
    )
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.SUPPLIER_NAME].satisfied is True
    assert report.compliant is True
    assert report.missing == []


def test_mixed_supplier_is_all_or_nothing():
    # One binary component with a supplier plus one package component without one
    # -> the all-or-nothing rule fails Supplier Name for the whole BOM, and the
    # detail reports the partial count.
    report = ntia.check(
        _sbom(
            sbom.Component(
                name="openssl", version="1.0.1f", source="binary",
                supplier="openssl",
            ),
            sbom.Component(name="zlib", version="1.2.11", source="dpkg"),
        )
    )
    by_el = {e.element: e for e in report.elements}
    supplier = by_el[ntia.SUPPLIER_NAME]
    assert supplier.satisfied is False
    assert supplier.components_satisfied == 1
    assert supplier.components_total == 2


def test_noassertion_supplier_does_not_count():
    comp = sbom.Component(name="curl", version="8.0", source="dpkg")
    comp.supplier = ntia.NOASSERTION  # type: ignore[attr-defined]
    report = ntia.check(_sbom(comp))
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.SUPPLIER_NAME].satisfied is False


def test_per_element_is_all_or_nothing():
    # One version-less component fails the Version element for the whole BOM.
    report = ntia.check(
        _sbom(
            sbom.Component(name="openssl", version="3.0", source="dpkg"),
            sbom.Component(name="busybox", version="", source="dpkg"),
        )
    )
    by_el = {e.element: e for e in report.elements}
    version = by_el[ntia.COMPONENT_VERSION]
    assert version.satisfied is False
    assert version.components_satisfied == 1
    assert version.components_total == 2


def test_empty_inventory_fails_per_component_elements():
    report = ntia.check(_sbom())
    by_el = {e.element: e for e in report.elements}
    for el in ntia.COMPONENT_ELEMENTS:
        assert by_el[el].satisfied is False, el
    assert report.component_count == 0
    assert report.compliant is False


def test_binary_component_identifier_via_cpe():
    # A binary-detected component still has a purl, and additionally a CPE; the
    # unique-identifier element is satisfied.
    report = ntia.check(
        _sbom(
            sbom.Component(
                name="openssl",
                version="1.1.1",
                source="binary",
                db_path="usr/lib/libssl.so",
                cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
            )
        )
    )
    by_el = {e.element: e for e in report.elements}
    assert by_el[ntia.UNIQUE_IDENTIFIER].satisfied is True


def test_satisfied_count_and_compliant_consistency():
    report = ntia.check(
        _sbom(sbom.Component(name="x", version="1", source="dpkg"))
    )
    assert report.satisfied_count == sum(1 for e in report.elements if e.satisfied)
    # 6/7: everything but Supplier Name.
    assert report.satisfied_count == 6
    assert report.compliant is False


# --- serialization ---------------------------------------------------------


def test_to_dict_shape():
    report = ntia.check(
        _sbom(sbom.Component(name="x", version="1", source="dpkg"))
    )
    d = report.to_dict()
    assert d["standard"].startswith("NTIA Minimum Elements")
    assert d["compliant"] is False
    assert d["component_count"] == 1
    assert d["elements_total"] == 7
    assert d["elements_satisfied"] == 6
    assert d["missing_elements"] == ["Supplier Name"]
    assert len(d["elements"]) == 7


def test_to_dict_is_json_serializable():
    report = ntia.check(
        _sbom(sbom.Component(name="x", version="1", source="dpkg"))
    )
    text = json.dumps(report.to_dict())
    assert "Supplier Name" in text


def test_element_result_omits_component_counts_for_document_elements():
    report = ntia.check(_sbom())
    by_el = {e.element: e for e in report.elements}
    author = by_el[ntia.SBOM_AUTHOR].to_dict()
    assert "components_total" not in author
    supplier = by_el[ntia.SUPPLIER_NAME].to_dict()
    assert supplier["components_total"] == 0


# --- Report integration ----------------------------------------------------


def test_report_omits_ntia_by_default():
    s = _sbom(sbom.Component(name="busybox", version="1.35", source="dpkg"))
    out = Report(firmware="router.bin", checks=["sbom"], sbom=s).to_dict()
    assert "ntia" not in out["sbom"]


def test_report_emits_ntia_under_sbom_key():
    s = _sbom(sbom.Component(name="busybox", version="1.35", source="dpkg"))
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.ntia = ntia.check(s)
    out = report.to_dict()
    assert "ntia" in out["sbom"]
    assert out["sbom"]["ntia"]["compliant"] is False
    # The BOM document still rides alongside the conformance report.
    assert "bom" in out["sbom"]


def test_markdown_renders_ntia_section():
    s = _sbom(sbom.Component(name="busybox", version="1.35", source="dpkg"))
    report = Report(firmware="router.bin", checks=["sbom"], sbom=s)
    report.ntia = ntia.check(s)
    md = report_mod.to_markdown(report)
    assert "NTIA minimum-elements conformance" in md
    assert "NOT COMPLIANT" in md
    assert "Supplier Name" in md


# --- pipeline integration --------------------------------------------------


def test_pipeline_ntia_off_by_default(fake_extracted_tree, monkeypatch):
    from embalmer import pipeline

    # Plant a dpkg database so the sbom check yields components.
    base = fake_extracted_tree / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    monkeypatch.setattr(
        extract, "extract", lambda *a, **k: _fake_extraction(fake_extracted_tree)
    )
    report = pipeline.run(
        firmware="fw.bin", workdir="x", checks="sbom", enrich=False
    )
    assert report.ntia is None


def test_pipeline_ntia_check_attaches_report(fake_extracted_tree, monkeypatch):
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
        ntia_check=True,
        enrich=False,
    )
    assert report.ntia is not None
    assert report.ntia.component_count >= 2  # busybox + openssl
    # Real firmware BOM: non-compliant on Supplier Name only.
    assert report.ntia.missing == ["Supplier Name"]


def test_pipeline_ntia_check_noop_without_sbom(fake_extracted_tree, monkeypatch):
    from embalmer import pipeline

    monkeypatch.setattr(
        extract, "extract", lambda *a, **k: _fake_extraction(fake_extracted_tree)
    )
    report = pipeline.run(
        firmware="fw.bin",
        workdir="x",
        checks="creds",
        ntia_check=True,
        enrich=False,
    )
    assert report.ntia is None


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


# --- CLI integration -------------------------------------------------------


def _plant_dpkg_tree(workdir):
    base = Path(workdir) / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)


@pytest.fixture
def _mock_extract(monkeypatch):
    monkeypatch.setattr(
        extract, "_run_unblob", lambda fw, wd: _plant_dpkg_tree(wd)
    )


def test_cli_sbom_ntia_check_json(sample_firmware, tmp_path, capsys, _mock_extract):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-ntia-check",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    nt = data["sbom"]["ntia"]
    assert nt["elements_total"] == 7
    assert nt["compliant"] is False
    assert nt["missing_elements"] == ["Supplier Name"]


def test_cli_without_flag_omits_ntia(sample_firmware, tmp_path, capsys, _mock_extract):
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
    assert "ntia" not in data["sbom"]


def test_cli_ntia_check_in_markdown(sample_firmware, tmp_path, capsys, _mock_extract):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-ntia-check",
            "--format",
            "md",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "NTIA minimum-elements conformance" in out
