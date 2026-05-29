"""Unit tests for the SPDX 2.3 SBOM export.

SPDX is, with CycloneDX, one of the two NTIA-recognized SBOM formats; embalmer
emits the same package inventory in both so the artifact drops into any
SPDX-aware consumer. These tests build real package-manager databases on disk
(Article IX: integration-first — real database files over mocks) and assert the
emitted SPDX document is spec-shaped, and that the `--sbom-format` selector
threads cleanly through the report and CLI while leaving the default CycloneDX
path byte-for-byte unchanged.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from embalmer import sbom
from embalmer.cli import main as cli_main
from embalmer.models import Report

# --- realistic database fixtures ------------------------------------------

_DPKG_STATUS = """\
Package: busybox
Status: install ok installed
Architecture: amd64
Version: 1.35.0-4
Description: Tiny utilities for small and embedded systems
 BusyBox combines tiny versions of many common UNIX utilities.

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
"""

_APK_INSTALLED = """\
C:Q1pXBqL5cZ8w==
P:musl
V:1.2.4-r2
A:x86_64
T:the musl c library (libc) implementation
L:MIT
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# --- SPDXID sanitization --------------------------------------------------


def test_spdx_id_fragment_sanitizes_disallowed_chars():
    # purl-ish / namespaced names contain slashes, tildes, plus signs.
    assert sbom._spdx_id_fragment("lib/curl") == "lib-curl"
    assert sbom._spdx_id_fragment("g++") == "g"
    assert sbom._spdx_id_fragment("uClibc-ng") == "uClibc-ng"
    # All-disallowed input still yields a valid (non-empty) fragment.
    assert sbom._spdx_id_fragment("///") == "x"


def test_component_spdx_id_is_unique_and_valid():
    a = sbom.Component(name="curl", version="1", source="dpkg")
    b = sbom.Component(name="curl", version="2", source="dpkg")
    id_a = a.spdx_id(0)
    id_b = b.spdx_id(1)
    assert id_a != id_b  # index disambiguates same-name components
    assert id_a.startswith("SPDXRef-")
    # SPDXID tail must match [A-Za-z0-9.-]; the slash-free fragment ensures it.
    tail = id_a[len("SPDXRef-") :]
    assert all(c.isalnum() or c in ".-" for c in tail)


# --- SPDX package object --------------------------------------------------


def test_component_to_spdx_package_shape():
    c = sbom.Component(
        name="openssl",
        version="3.0.11",
        source="dpkg",
        description="Secure Sockets Layer toolkit",
    )
    pkg = c.to_spdx("SPDXRef-Package-0-openssl")
    assert pkg["SPDXID"] == "SPDXRef-Package-0-openssl"
    assert pkg["name"] == "openssl"
    assert pkg["versionInfo"] == "3.0.11"
    # SPDX mandates these on every package.
    assert pkg["downloadLocation"] == "NOASSERTION"
    assert pkg["licenseConcluded"] == "NOASSERTION"
    assert pkg["filesAnalyzed"] is False
    # purl carried as a PACKAGE-MANAGER externalRef.
    purl_refs = [
        r for r in pkg["externalRefs"] if r["referenceType"] == "purl"
    ]
    assert len(purl_refs) == 1
    assert purl_refs[0]["referenceLocator"] == c.purl()
    assert pkg["description"] == "Secure Sockets Layer toolkit"


def test_component_to_spdx_declares_known_license():
    c = sbom.Component(name="musl", version="1.2.4-r2", source="apk", license_id="MIT")
    pkg = c.to_spdx("SPDXRef-Package-0-musl")
    assert pkg["licenseDeclared"] == "MIT"


def test_binary_component_to_spdx_carries_cpe():
    c = sbom.Component(
        name="openssl",
        version="1.0.1f",
        source="binary",
        cpe="cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        db_path="usr/bin/httpd",
    )
    pkg = c.to_spdx("SPDXRef-Package-0-openssl")
    cpe_refs = [
        r for r in pkg["externalRefs"] if r["referenceType"] == "cpe23Type"
    ]
    assert len(cpe_refs) == 1
    assert cpe_refs[0]["referenceCategory"] == "SECURITY"
    assert cpe_refs[0]["referenceLocator"] == c.cpe


# --- SPDX document --------------------------------------------------------


def test_spdx_document_shape(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    ts = datetime.datetime(2026, 5, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)
    doc = result.to_spdx("router.bin", timestamp=ts)

    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["creationInfo"]["created"] == "2026-05-28T12:00:00Z"
    assert any("embalmer" in c for c in doc["creationInfo"]["creators"])
    # documentNamespace must be present and unique-ish (carries the timestamp).
    assert "router.bin" in doc["documentNamespace"]
    assert "2026-05-28T12:00:00Z" in doc["documentNamespace"]


def test_spdx_document_has_root_firmware_package(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    doc = sbom.scan(root).to_spdx("router.bin")
    root_pkg = next(
        p for p in doc["packages"] if p["SPDXID"] == "SPDXRef-Package-firmware"
    )
    assert root_pkg["name"] == "router.bin"
    # The document DESCRIBES the firmware root.
    assert any(
        r["relationshipType"] == "DESCRIBES"
        and r["relatedSpdxElement"] == "SPDXRef-Package-firmware"
        for r in doc["relationships"]
    )


def test_spdx_packages_and_contains_relationships(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    doc = result.to_spdx("router.bin")

    # One firmware root + one package per component.
    assert len(doc["packages"]) == len(result.components) + 1
    names = {p["name"] for p in doc["packages"]}
    assert {"busybox", "openssl", "router.bin"} <= names

    # Every component package is CONTAINS-related to the firmware root.
    contains = [
        r for r in doc["relationships"] if r["relationshipType"] == "CONTAINS"
    ]
    assert len(contains) == len(result.components)
    comp_ids = {
        p["SPDXID"]
        for p in doc["packages"]
        if p["SPDXID"] != "SPDXRef-Package-firmware"
    }
    assert {r["relatedSpdxElement"] for r in contains} == comp_ids


def test_spdx_all_spdxids_unique_and_valid(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    _write(root / "lib" / "apk" / "db" / "installed", _APK_INSTALLED)

    doc = sbom.scan(root).to_spdx("router.bin")
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids))  # unique
    for spdx_id in ids:
        assert spdx_id.startswith("SPDXRef-")
        tail = spdx_id[len("SPDXRef-") :]
        assert all(c.isalnum() or c in ".-" for c in tail)


def test_spdx_empty_inventory_still_valid(tmp_path: Path):
    root = tmp_path / "extract"
    (root / "etc").mkdir(parents=True)
    doc = sbom.scan(root).to_spdx("router.bin")
    # No components: just the firmware root package and its DESCRIBES edge.
    assert len(doc["packages"]) == 1
    assert doc["packages"][0]["SPDXID"] == "SPDXRef-Package-firmware"
    assert doc["relationships"] == [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-firmware",
        }
    ]


def test_spdx_is_json_serializable(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    doc = sbom.scan(root).to_spdx("router.bin")
    # Round-trips through JSON without error or data loss.
    assert json.loads(json.dumps(doc)) == doc


# --- render() format selector ---------------------------------------------


def test_render_cyclonedx_only(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    out = sbom.scan(root).render("router.bin", "cyclonedx")
    assert set(out) == {"cyclonedx"}
    assert out["cyclonedx"]["bomFormat"] == "CycloneDX"


def test_render_spdx_only(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    out = sbom.scan(root).render("router.bin", "spdx")
    assert set(out) == {"spdx"}
    assert out["spdx"]["spdxVersion"] == "SPDX-2.3"


def test_render_both(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    out = sbom.scan(root).render("router.bin", "both")
    assert set(out) == {"cyclonedx", "spdx"}


def test_render_unknown_format_raises(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    try:
        sbom.scan(root).render("router.bin", "bogus")
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for unknown format")


# --- Report integration ---------------------------------------------------


def _report_with_sbom(sbom_format: str) -> dict:
    s = sbom.Sbom(
        components=[
            sbom.Component(name="busybox", version="1.35.0", source="dpkg"),
        ]
    )
    report = Report(
        firmware="router.bin",
        checks=["sbom"],
        sbom=s,
        sbom_format=sbom_format,
    )
    return report.to_dict()


def test_report_default_emits_cyclonedx_bom_unchanged():
    # Default path keeps the historical `bom` key and no `spdx` key.
    out = _report_with_sbom("cyclonedx")
    assert "bom" in out["sbom"]
    assert out["sbom"]["bom"]["bomFormat"] == "CycloneDX"
    assert "spdx" not in out["sbom"]


def test_report_spdx_emits_spdx_key_only():
    out = _report_with_sbom("spdx")
    assert "spdx" in out["sbom"]
    assert out["sbom"]["spdx"]["spdxVersion"] == "SPDX-2.3"
    assert "bom" not in out["sbom"]


def test_report_both_emits_both():
    out = _report_with_sbom("both")
    assert "bom" in out["sbom"]
    assert "spdx" in out["sbom"]


def test_report_default_sbom_format_is_cyclonedx():
    # An unset sbom_format must preserve the legacy behavior.
    s = sbom.Sbom(components=[])
    report = Report(firmware="x.bin", checks=["sbom"], sbom=s)
    out = report.to_dict()
    assert "bom" in out["sbom"]
    assert "spdx" not in out["sbom"]


# --- CLI integration ------------------------------------------------------
#
# Extraction is mocked at the unblob seam (as in test_smoke.py) so these run
# without unblob installed; the mocked extraction plants a real dpkg database so
# the sbom check produces components.

import pytest  # noqa: E402

from embalmer import extract  # noqa: E402


def _plant_dpkg_tree(workdir):
    base = Path(workdir) / "sample-firmware.bin_extract"
    _write(base / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)


@pytest.fixture
def _mock_extract(monkeypatch):
    monkeypatch.setattr(
        extract, "_run_unblob", lambda fw, wd: _plant_dpkg_tree(wd)
    )


def test_cli_sbom_format_spdx(sample_firmware, tmp_path, capsys, _mock_extract):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-format",
            "spdx",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["sbom"]["spdx"]["spdxVersion"] == "SPDX-2.3"
    assert any(
        p["name"] == "busybox" for p in data["sbom"]["spdx"]["packages"]
    )
    assert "bom" not in data["sbom"]


def test_cli_sbom_format_both(sample_firmware, tmp_path, capsys, _mock_extract):
    rc = cli_main(
        [
            "--firmware",
            str(sample_firmware),
            "--workdir",
            str(tmp_path / "work"),
            "--checks",
            "sbom",
            "--sbom-format",
            "both",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "bom" in data["sbom"]
    assert "spdx" in data["sbom"]


def test_cli_sbom_format_default_is_cyclonedx(
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
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "bom" in data["sbom"]
    assert "spdx" not in data["sbom"]


def test_cli_spdx_note_in_markdown(
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
            "--sbom-format",
            "spdx",
            "--format",
            "md",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "SPDX-2.3" in out
    assert "sbom.spdx" in out


def test_cli_rejects_unknown_sbom_format(sample_firmware):
    with pytest.raises(SystemExit):
        cli_main(
            [
                "--firmware",
                str(sample_firmware),
                "--checks",
                "sbom",
                "--sbom-format",
                "bogus",
            ]
        )
