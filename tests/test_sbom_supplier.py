"""Unit tests for the SBOM supplier-metadata compliance check.

The supplier-check scores every SBOM component on whether it carries an
asserted (non-empty, non-``NOASSERTION``) supplier and attaches a per-component
pass/fail verdict under ``sbom.suppliers``. It is the metadata-transparency
companion to the procurement gates already shipped:

  * ``--sbom-license-check``       gates on *what license a component carries*;
  * ``--component-blocklist``      gates on *which component is shipping*;
  * ``--sbom-supplier-check`` (this) gates on *who supplied each component*.

These tests exercise:

  * per-component supplier detection (asserted / empty / NOASSERTION sentinel);
  * the per-component / overall report shape and the ``to_dict`` round-trip;
  * the pipeline integration (``--sbom-supplier-check``) end-to-end through the
    CLI, the JSON report, and the markdown renderer;
  * the ``--fail-on`` gate composition: a missing supplier counts as a
    ``medium`` severity finding and trips the gate at exit code 10.
"""

from __future__ import annotations

import json
from pathlib import Path

from embalmer import sbom, sbom_supplier
from embalmer.cli import main as cli_main
from embalmer.gate import GATE_EXIT_CODE, evaluate as evaluate_gate
from embalmer.models import Report
from embalmer import report as report_mod


# --- helpers ----------------------------------------------------------------


def _comp(
    name: str,
    version: str,
    supplier: str | None = None,
    source: str = "dpkg",
) -> sbom.Component:
    return sbom.Component(
        name=name,
        version=version,
        source=source,
        architecture=None,
        db_path=f"var/lib/{source}/status",
        supplier=supplier,
    )


def _sbom(*components: sbom.Component) -> sbom.Sbom:
    return sbom.Sbom(components=list(components))


# --- per-component supplier detection ---------------------------------------


def test_component_with_asserted_supplier_passes():
    c = _comp("openssl", "1.0.1f", supplier="haxx")
    assert sbom_supplier._component_has_supplier(c) is True


def test_component_with_none_supplier_fails():
    # A package-database component (no upstream resolution) leaves supplier
    # as None on the dataclass — embalmer surfaces NOASSERTION downstream, but
    # the in-memory check sees None and must count it as a fail.
    c = _comp("openssl", "1.0.1f", supplier=None)
    assert sbom_supplier._component_has_supplier(c) is False


def test_component_with_empty_supplier_fails():
    c = _comp("openssl", "1.0.1f", supplier="")
    assert sbom_supplier._component_has_supplier(c) is False


def test_component_with_noassertion_supplier_fails():
    # NOASSERTION is the SPDX sentinel for "not determined" — the honest
    # posture embalmer takes when it cannot resolve the supplier from
    # firmware. The supplier check must treat it as a fail, not a pass.
    c = _comp("openssl", "1.0.1f", supplier="NOASSERTION")
    assert sbom_supplier._component_has_supplier(c) is False


# --- check() over an SBOM ---------------------------------------------------


def test_check_empty_sbom_is_compliant():
    # Vacuously compliant — no component fails because there are no
    # components (matches the symmetric posture of the blocklist check).
    rep = sbom_supplier.check(_sbom())
    assert rep.compliant is True
    assert rep.component_count == 0
    assert rep.missing_components == []
    assert rep.asserted_count == 0


def test_check_all_components_have_supplier_is_compliant():
    s = _sbom(
        _comp("openssl", "1.0.1f", supplier="haxx"),
        _comp("busybox", "1.30", supplier="busybox"),
    )
    rep = sbom_supplier.check(s)
    assert rep.compliant is True
    assert rep.component_count == 2
    assert rep.asserted_count == 2
    assert rep.missing_components == []


def test_check_any_component_missing_supplier_is_non_compliant():
    s = _sbom(
        _comp("openssl", "1.0.1f", supplier="haxx"),
        _comp("zlib", "1.2.11", supplier=None),
    )
    rep = sbom_supplier.check(s)
    assert rep.compliant is False
    assert rep.component_count == 2
    assert rep.asserted_count == 1
    missing_names = [c.name for c in rep.missing_components]
    assert missing_names == ["zlib"]


def test_check_records_every_component_uniformly():
    # Every component must appear in the per-component verdict list — the
    # report is a uniform inventory, not just a list of failures.
    s = _sbom(
        _comp("a", "1.0", supplier="A"),
        _comp("b", "1.0", supplier=None),
        _comp("c", "1.0", supplier="NOASSERTION"),
    )
    rep = sbom_supplier.check(s)
    assert rep.component_count == 3
    assert [c.has_supplier for c in rep.components] == [True, False, False]


def test_check_noassertion_string_treated_as_missing():
    s = _sbom(_comp("openssl", "1.0.1f", supplier="NOASSERTION"))
    rep = sbom_supplier.check(s)
    assert rep.compliant is False
    assert len(rep.missing_components) == 1
    assert rep.missing_components[0].supplier == "NOASSERTION"


# --- report shape / to_dict round-trip --------------------------------------


def test_to_dict_shape_includes_every_documented_field():
    s = _sbom(
        _comp("openssl", "1.0.1f", supplier="haxx"),
        _comp("zlib", "1.2.11", supplier=None),
    )
    rep = sbom_supplier.check(s)
    d = rep.to_dict()
    assert d["standard"] == "SBOM supplier-metadata compliance"
    assert d["compliant"] is False
    assert d["component_count"] == 2
    assert d["asserted_count"] == 1
    assert d["missing_count"] == 1
    assert len(d["components"]) == 2
    # Asserted component: no severity key.
    asserted = next(c for c in d["components"] if c["name"] == "openssl")
    assert asserted["has_supplier"] is True
    assert asserted["supplier"] == "haxx"
    assert "severity" not in asserted
    # Missing-supplier component: severity at the gate-friendly tier.
    missing = next(c for c in d["components"] if c["name"] == "zlib")
    assert missing["has_supplier"] is False
    assert missing["supplier"] is None
    assert missing["severity"] == sbom_supplier.MISSING_SUPPLIER_SEVERITY


def test_to_dict_purl_is_the_sbom_purl():
    # The verdict's purl must match the SBOM component's purl exactly — so a
    # downstream consumer can join the supplier verdict to the SBOM by purl.
    c = _comp("openssl", "1.0.1f", supplier="haxx")
    rep = sbom_supplier.check(_sbom(c))
    assert rep.components[0].purl == c.purl()


def test_supplier_component_severity_property():
    c_ok = sbom_supplier.SupplierComponent(
        purl="pkg:deb/x@1", name="x", version="1", supplier="upstream"
    )
    assert c_ok.severity is None
    c_bad = sbom_supplier.SupplierComponent(
        purl="pkg:deb/x@1", name="x", version="1", supplier=None
    )
    assert c_bad.severity == sbom_supplier.MISSING_SUPPLIER_SEVERITY


# --- Report integration -----------------------------------------------------


def test_report_to_dict_attaches_under_sbom_suppliers():
    s = _sbom(_comp("openssl", "1.0.1f", supplier=None))
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    d = report.to_dict()
    assert "sbom" in d
    assert "suppliers" in d["sbom"]
    assert d["sbom"]["suppliers"]["compliant"] is False
    assert d["sbom"]["suppliers"]["missing_count"] == 1


def test_report_to_dict_omits_when_check_not_requested():
    s = _sbom(_comp("openssl", "1.0.1f", supplier=None))
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    d = report.to_dict()
    assert "suppliers" not in d["sbom"]


# --- gate composition ------------------------------------------------------


def test_gate_observes_missing_supplier_as_medium_severity():
    # Pairing --sbom-supplier-check with --fail-on medium must trip CI on a
    # missing supplier — the supplier gate composes with the existing
    # severity ladder the same way the blocklist gate does.
    s = _sbom(
        _comp("openssl", "1.0.1f", supplier="haxx"),
        _comp("zlib", "1.2.11", supplier=None),
    )
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    verdict = evaluate_gate(report, "medium")
    assert verdict.triggered is True
    assert verdict.counts.get("medium", 0) >= 1


def test_gate_does_not_trip_when_every_component_has_supplier():
    s = _sbom(_comp("openssl", "1.0.1f", supplier="haxx"))
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    verdict = evaluate_gate(report, "medium")
    assert verdict.triggered is False


def test_gate_at_high_threshold_does_not_trip_on_missing_supplier():
    # The supplier gate is `medium`-tier; an operator running --fail-on high
    # must not see a missing supplier alone trip CI (the gap is a real signal
    # but weaker than a procurement-policy violation).
    s = _sbom(_comp("zlib", "1.2.11", supplier=None))
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    verdict = evaluate_gate(report, "high")
    assert verdict.triggered is False


# --- markdown rendering ----------------------------------------------------


def test_markdown_renders_supplier_subsection_with_missing_table():
    s = _sbom(
        _comp("openssl", "1.0.1f", supplier="haxx"),
        _comp("zlib", "1.2.11", supplier=None),
    )
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    md = report_mod.render(report, "md")
    assert "### Supplier-metadata compliance" in md
    assert "NOT COMPLIANT" in md
    assert "1 of 2 component(s) carry an asserted supplier" in md
    assert "**Components missing a supplier:**" in md
    assert "| zlib | 1.2.11 | (none) |" in md


def test_markdown_renders_compliant_verdict_without_missing_table():
    s = _sbom(_comp("openssl", "1.0.1f", supplier="haxx"))
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    md = report_mod.render(report, "md")
    assert "### Supplier-metadata compliance" in md
    assert "COMPLIANT" in md
    assert "**Components missing a supplier:**" not in md


def test_markdown_renders_noassertion_declared_value():
    # An explicit NOASSERTION supplier must show up verbatim in the "Declared
    # supplier" column so an auditor can distinguish a None-supplier from a
    # NOASSERTION-supplier (both fail, but they say different things about
    # what the upstream tooling did).
    s = _sbom(_comp("openssl", "1.0.1f", supplier="NOASSERTION"))
    sup_report = sbom_supplier.check(s)
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.sbom_supplier = sup_report
    md = report_mod.render(report, "md")
    assert "| openssl | 1.0.1f | NOASSERTION |" in md


# --- pipeline / CLI integration --------------------------------------------


def _planted_dpkg_fixture(tmp_path: Path) -> Path:
    """Plant a minimal extracted-firmware tree with a dpkg status DB.

    Two packages: the resulting SBOM components carry no resolved supplier
    (dpkg parsing does not set the Component.supplier field), so the
    supplier check has two failures to surface end-to-end.
    """
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"fake firmware")
    extract_root = tmp_path / "work" / "extract"
    dpkg_dir = extract_root / "var" / "lib" / "dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text(
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 1.0.1f\n"
        "Architecture: amd64\n"
        "\n"
        "Package: zlib\n"
        "Status: install ok installed\n"
        "Version: 1.2.11\n"
        "Architecture: amd64\n"
        "\n"
    )
    return fw


def _stub_extract(tmp_path, monkeypatch):
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    def fake_extract(firmware, workdir_path, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=2,
            extraction_time_ms=0,
            extract_root=str(tmp_path / "work" / "extract"),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)


def test_cli_sbom_supplier_check_end_to_end_flags_missing(
    tmp_path, monkeypatch, capsys
):
    fw = _planted_dpkg_fixture(tmp_path)
    workdir = tmp_path / "work"
    _stub_extract(tmp_path, monkeypatch)

    rc = cli_main(
        [
            "--firmware",
            str(fw),
            "--workdir",
            str(workdir),
            "--checks",
            "sbom",
            "--sbom-supplier-check",
            "--no-enrich",
        ]
    )
    assert rc == 0  # the check itself does not change exit code without --fail-on
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "suppliers" in data["sbom"]
    sup = data["sbom"]["suppliers"]
    assert sup["compliant"] is False
    assert sup["component_count"] == 2
    assert sup["missing_count"] == 2
    missing_names = sorted(
        c["name"] for c in sup["components"] if not c["has_supplier"]
    )
    assert missing_names == ["openssl", "zlib"]


def test_cli_sbom_supplier_check_composes_with_fail_on_gate(
    tmp_path, monkeypatch, capsys
):
    fw = _planted_dpkg_fixture(tmp_path)
    workdir = tmp_path / "work"
    _stub_extract(tmp_path, monkeypatch)

    rc = cli_main(
        [
            "--firmware",
            str(fw),
            "--workdir",
            str(workdir),
            "--checks",
            "sbom",
            "--sbom-supplier-check",
            "--fail-on",
            "medium",
            "--no-enrich",
        ]
    )
    assert rc == GATE_EXIT_CODE


def test_cli_sbom_supplier_check_default_off_leaves_report_unchanged(
    tmp_path, monkeypatch, capsys
):
    # Off by default: a run without --sbom-supplier-check must not include
    # the `suppliers` key under `sbom`. Existing report consumers stay
    # byte-for-byte unaffected.
    fw = _planted_dpkg_fixture(tmp_path)
    workdir = tmp_path / "work"
    _stub_extract(tmp_path, monkeypatch)

    rc = cli_main(
        [
            "--firmware",
            str(fw),
            "--workdir",
            str(workdir),
            "--checks",
            "sbom",
            "--no-enrich",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "sbom" in data
    assert "suppliers" not in data["sbom"]
