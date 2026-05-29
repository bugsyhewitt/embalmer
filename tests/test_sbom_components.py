"""Unit tests for the components -> SBOM cross-link.

The ``components`` check recovers third-party libraries from binaries' baked-in
version strings (OpenSSL, BusyBox, …) — statically-linked dependencies that no
package-manager database lists. This cross-link folds those findings into the
CycloneDX SBOM so the BOM is the single, complete component inventory.

These tests exercise the merge at three layers (Article IX: real files / real
findings over mocks):

  * ``Component.from_component_finding`` / ``purl`` / ``to_cyclonedx`` — the
    binary-sourced component shape;
  * ``Sbom.merge_component_findings`` — the dedup-against-package-DB behavior;
  * the full pipeline — both checks run, the SBOM reflects the merge.
"""

from __future__ import annotations

from pathlib import Path

from embalmer import components, pipeline, sbom
from embalmer.models import Finding
from embalmer.sbom import Component, Sbom


# --- Component.from_component_finding --------------------------------------


def _component_finding(
    name: str,
    version: str,
    path: str = "usr/lib/lib.so",
    vendor: str | None = None,
) -> Finding:
    extra = {
        "component": name,
        "version": version,
        "cpe": f"cpe:2.3:a:{vendor or name}:{name}:{version}:*:*:*:*:*:*:*",
    }
    if vendor is not None:
        extra["vendor"] = vendor
    return Finding(
        category="component",
        path=path,
        type=name,
        detail=f"{name} {version}",
        severity="info",
        extra=extra,
    )


def test_from_component_finding_builds_binary_sourced_component():
    finding = _component_finding("openssl", "1.0.1f", path="usr/lib/libcrypto.so")
    comp = Component.from_component_finding(finding)
    assert comp is not None
    assert comp.name == "openssl"
    assert comp.version == "1.0.1f"
    assert comp.source == "binary"
    # db_path records the binary the banner came from, not a package database.
    assert comp.db_path == "usr/lib/libcrypto.so"
    assert comp.cpe == "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*"


def test_from_component_finding_carries_vendor_as_supplier():
    # The components check records the upstream CPE vendor; it becomes the
    # binary-detected component's asserted supplier (the NTIA Supplier element).
    finding = _component_finding("curl", "7.79.1", vendor="haxx")
    comp = Component.from_component_finding(finding)
    assert comp is not None
    assert comp.supplier == "haxx"


def test_from_component_finding_without_vendor_leaves_supplier_none():
    # An older finding shape carrying no vendor must not crash and must leave the
    # supplier unasserted rather than inventing one.
    finding = _component_finding("curl", "7.79.1")  # no vendor
    comp = Component.from_component_finding(finding)
    assert comp is not None
    assert comp.supplier is None


def test_from_component_finding_returns_none_without_metadata():
    # A finding lacking component/version metadata cannot become a component.
    bare = Finding(category="component", path="x", type="?", extra={})
    assert Component.from_component_finding(bare) is None


def test_binary_component_purl_is_generic():
    comp = Component.from_component_finding(_component_finding("busybox", "1.35.0"))
    assert comp is not None
    # Not package-managed -> purl uses the generic namespace.
    assert comp.purl() == "pkg:generic/busybox@1.35.0"


def test_binary_component_cyclonedx_carries_cpe_and_provenance():
    comp = Component.from_component_finding(
        _component_finding("openssl", "1.0.1f", path="usr/lib/libcrypto.so")
    )
    assert comp is not None
    cdx = comp.to_cyclonedx()
    assert cdx["type"] == "library"
    assert cdx["name"] == "openssl"
    assert cdx["version"] == "1.0.1f"
    # CPE goes in CycloneDX's first-class field for vuln-db matching.
    assert cdx["cpe"] == "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*"
    prop_names = {p["name"]: p["value"] for p in cdx["properties"]}
    assert prop_names["embalmer:detected-from"] == "binary-strings"
    assert prop_names["embalmer:binary"] == "usr/lib/libcrypto.so"


def test_binary_component_cyclonedx_carries_supplier():
    # A binary-detected component's upstream vendor is emitted as the CycloneDX
    # first-class `supplier` organizationalEntity.
    comp = Component.from_component_finding(
        _component_finding("curl", "7.79.1", vendor="haxx")
    )
    assert comp is not None
    cdx = comp.to_cyclonedx()
    assert cdx["supplier"] == {"name": "haxx"}


def test_binary_component_spdx_carries_supplier():
    # SPDX requires `Organization:`/`Person:`/NOASSERTION; an asserted supplier
    # is emitted as an Organization entity.
    comp = Component.from_component_finding(
        _component_finding("curl", "7.79.1", vendor="haxx")
    )
    assert comp is not None
    pkg = comp.to_spdx("SPDXRef-Package-0-curl")
    assert pkg["supplier"] == "Organization: haxx"


def test_package_component_supplier_stays_noassertion():
    # A package-DB component has no asserted supplier (the DB names a packager,
    # not the upstream supplier) -> CycloneDX omits it, SPDX emits NOASSERTION.
    comp = Component(name="curl", version="7.79.1", source="dpkg")
    assert "supplier" not in comp.to_cyclonedx()
    assert comp.to_spdx("SPDXRef-Package-0-curl")["supplier"] == "NOASSERTION"


def test_package_component_cyclonedx_unchanged_no_cpe():
    # A package-DB component still renders with package-manager provenance and no
    # cpe field (it is identified by its purl) — the merge must not regress this.
    comp = Component(name="curl", version="7.79.1", source="dpkg", db_path="var/lib/dpkg/status")
    cdx = comp.to_cyclonedx()
    assert "cpe" not in cdx
    prop_names = {p["name"]: p["value"] for p in cdx["properties"]}
    assert prop_names["embalmer:package-manager"] == "dpkg"
    assert prop_names["embalmer:database"] == "var/lib/dpkg/status"


# --- Sbom.merge_component_findings -----------------------------------------


def test_merge_adds_binary_only_components():
    bom = Sbom(components=[Component(name="curl", version="7.79.1", source="dpkg")])
    bom.merge_component_findings(
        [
            _component_finding("openssl", "1.0.1f"),
            _component_finding("busybox", "1.35.0"),
        ]
    )
    names = {(c.source, c.name, c.version) for c in bom.components}
    assert ("dpkg", "curl", "7.79.1") in names
    assert ("binary", "openssl", "1.0.1f") in names
    assert ("binary", "busybox", "1.35.0") in names


def test_merge_dedups_against_package_db():
    # OpenSSL 3.0.11 is already in the SBOM from the package DB; the binary banner
    # for the same name+version must not produce a duplicate component.
    bom = Sbom(components=[Component(name="openssl", version="3.0.11", source="dpkg")])
    bom.merge_component_findings([_component_finding("openssl", "3.0.11")])
    openssls = [c for c in bom.components if c.name == "openssl"]
    assert len(openssls) == 1
    # The package-DB record (authoritative) is kept, not the binary one.
    assert openssls[0].source == "dpkg"


def test_merge_keeps_different_version_of_same_name():
    # A statically-linked OpenSSL 1.0.1f alongside a packaged OpenSSL 3.0.11 is
    # two genuinely different components — both must survive.
    bom = Sbom(components=[Component(name="openssl", version="3.0.11", source="dpkg")])
    bom.merge_component_findings([_component_finding("openssl", "1.0.1f")])
    versions = sorted(c.version for c in bom.components if c.name == "openssl")
    assert versions == ["1.0.1f", "3.0.11"]


def test_merge_dedups_among_binary_findings():
    # The same component banner in two binaries -> one merged component.
    bom = Sbom(components=[])
    bom.merge_component_findings(
        [
            _component_finding("busybox", "1.35.0", path="bin/busybox"),
            _component_finding("busybox", "1.35.0", path="sbin/busybox"),
        ]
    )
    bb = [c for c in bom.components if c.name == "busybox"]
    assert len(bb) == 1
    # First occurrence wins (stable order).
    assert bb[0].db_path == "bin/busybox"


def test_merge_skips_findings_without_metadata():
    bom = Sbom(components=[])
    bom.merge_component_findings([Finding(category="component", path="x", type="?")])
    assert bom.components == []


def test_merged_component_in_to_dict_and_bom():
    bom = Sbom(components=[Component(name="curl", version="7.79.1", source="dpkg")])
    bom.merge_component_findings([_component_finding("openssl", "1.0.1f")])
    d = bom.to_dict()
    assert d["component_count"] == 2
    summary = {(c["source"], c["name"], c["version"]): c for c in d["components"]}
    binary = summary[("binary", "openssl", "1.0.1f")]
    assert binary["purl"] == "pkg:generic/openssl@1.0.1f"
    assert binary["cpe"] == "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*"
    # The CycloneDX BOM contains the merged component too.
    cdx = bom.to_cyclonedx("fw.bin")
    cdx_names = {(c["name"], c["version"]) for c in cdx["components"]}
    assert ("openssl", "1.0.1f") in cdx_names
    assert ("curl", "7.79.1") in cdx_names


# --- pipeline integration --------------------------------------------------


def _write_firmware_tree(tmp_path: Path) -> Path:
    """An extracted tree with both a package DB and a statically-linked lib."""
    root = tmp_path / "extract"
    (root / "var" / "lib" / "dpkg").mkdir(parents=True)
    (root / "usr" / "lib").mkdir(parents=True)
    # Package DB lists curl only.
    (root / "var" / "lib" / "dpkg" / "status").write_text(
        "Package: curl\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 7.79.1-1\n"
        "Description: command line tool for transferring data\n"
    )
    # libcrypto carries an OpenSSL banner but is in no package DB.
    blob = b"\x7fELF\x00\x00OpenSSL 1.0.1f 6 Jan 2014\x00\x00"
    (root / "usr" / "lib" / "libcrypto.so").write_bytes(blob)
    return root


def _patch_extract(monkeypatch, root: Path):
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    result = ExtractionResult(
        extraction_tree={},
        file_count=2,
        extraction_time_ms=1,
        extract_root=str(root),
        extractor_used="unblob",
    )
    monkeypatch.setattr(
        extract_mod, "extract", lambda *a, **k: result
    )
    monkeypatch.setattr(pipeline.extract, "extract", lambda *a, **k: result)


def test_pipeline_merges_components_into_sbom(tmp_path, monkeypatch):
    root = _write_firmware_tree(tmp_path)
    _patch_extract(monkeypatch, root)

    report = pipeline.run(
        firmware="fw.bin",
        workdir=tmp_path / "wd",
        checks="all",
        enrich=False,
        _blight_analyzer=lambda _path: [],
    )

    assert report.sbom is not None
    inventory = {(c.source, c.name) for c in report.sbom.components}
    # curl from the package DB, OpenSSL folded in from the binary banner.
    assert ("dpkg", "curl") in inventory
    assert ("binary", "openssl") in inventory


def test_pipeline_binary_component_carries_supplier(tmp_path, monkeypatch):
    # End-to-end: the OpenSSL banner in libcrypto.so is detected, folded into the
    # SBOM, and arrives carrying its upstream vendor as the asserted supplier.
    root = _write_firmware_tree(tmp_path)
    _patch_extract(monkeypatch, root)

    report = pipeline.run(
        firmware="fw.bin",
        workdir=tmp_path / "wd",
        checks="all",
        enrich=False,
        _blight_analyzer=lambda _path: [],
    )

    assert report.sbom is not None
    openssl = next(
        c for c in report.sbom.components if c.source == "binary" and c.name == "openssl"
    )
    assert openssl.supplier == "openssl"
    # The CycloneDX rendering carries the supplier entity.
    cdx = report.sbom.to_cyclonedx("fw.bin")
    ssl_cdx = next(c for c in cdx["components"] if c["name"] == "openssl")
    assert ssl_cdx["supplier"] == {"name": "openssl"}


def test_pipeline_sbom_without_components_check_is_not_merged(tmp_path, monkeypatch):
    # Running sbom alone (no components check) leaves the SBOM as the package-DB
    # inventory only — the merge is gated on both checks running.
    root = _write_firmware_tree(tmp_path)
    _patch_extract(monkeypatch, root)

    report = pipeline.run(
        firmware="fw.bin", workdir=tmp_path / "wd", checks="sbom", enrich=False
    )

    assert report.sbom is not None
    sources = {c.source for c in report.sbom.components}
    assert sources == {"dpkg"}


def test_pipeline_components_without_sbom_check_no_crash(tmp_path, monkeypatch):
    # Running components alone leaves sbom None; the merge guard must not fire.
    root = _write_firmware_tree(tmp_path)
    _patch_extract(monkeypatch, root)

    report = pipeline.run(
        firmware="fw.bin", workdir=tmp_path / "wd", checks="components", enrich=False
    )

    assert report.sbom is None
    assert report.components
