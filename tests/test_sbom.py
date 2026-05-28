"""Unit tests for the SBOM (CycloneDX) generator.

Builds real package-manager database files on disk (dpkg status, opkg status +
.control files, apk installed) with genuine deb822/apk stanza content, then
asserts the scanner produces a correct component inventory and a spec-compliant
CycloneDX 1.6 BOM (Article IX: integration-first — real database files over
mocks).
"""

from __future__ import annotations

import datetime
from pathlib import Path

from embalmer import sbom

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

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0.0
Description: A package that was removed; must NOT appear in the SBOM.

Package: nover-pkg
Status: install ok installed
Architecture: amd64
Description: A package with no version; must be skipped.
"""

_OPKG_STATUS = """\
Package: dropbear
Version: 2022.83-5
Depends: libc, zlib
Status: install user installed
Architecture: mips_24kc
Installed-Time: 1700000000

Package: uhttpd
Version: 2021-03-23
Status: install user installed
Architecture: mips_24kc
"""

_OPKG_CONTROL_CURL = """\
Package: curl
Version: 7.88.1-1
Depends: libcurl4
Status: install user installed
Architecture: mips_24kc
Description: A client-side URL transfer utility
"""

_APK_INSTALLED = """\
C:Q1pXBqL5cZ8w==
P:musl
V:1.2.4-r2
A:x86_64
T:the musl c library (libc) implementation
L:MIT
S:383152
I:622592

C:Q1aBcDeF==
P:zlib
V:1.2.13-r1
A:x86_64
T:A compression/decompression Library
L:Zlib
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# --- stanza parser --------------------------------------------------------


def test_parse_stanzas_splits_on_blank_lines():
    text = "A: 1\nB: 2\n\nA: 3\n"
    stanzas = sbom._parse_stanzas(text)
    assert stanzas == [{"A": "1", "B": "2"}, {"A": "3"}]


def test_parse_stanzas_handles_continuation_lines():
    text = "Description: first line\n more detail\n even more\nVersion: 1.0\n"
    stanzas = sbom._parse_stanzas(text)
    assert len(stanzas) == 1
    assert stanzas[0]["Description"] == "first line\nmore detail\neven more"
    assert stanzas[0]["Version"] == "1.0"


def test_parse_stanzas_ignores_lines_without_colon():
    text = "Package: foo\ngarbage line without colon\nVersion: 1\n"
    stanzas = sbom._parse_stanzas(text)
    assert stanzas == [{"Package": "foo", "Version": "1"}]


# --- dpkg -----------------------------------------------------------------


def test_dpkg_components_extracted(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    names = {c.name for c in result.components}
    assert "busybox" in names
    assert "openssl" in names


def test_dpkg_removed_package_excluded(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    names = {c.name for c in result.components}
    assert "removed-pkg" not in names


def test_dpkg_versionless_package_skipped(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    names = {c.name for c in result.components}
    assert "nover-pkg" not in names


def test_dpkg_component_fields(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    busybox = next(c for c in result.components if c.name == "busybox")
    assert busybox.version == "1.35.0-4"
    assert busybox.architecture == "amd64"
    assert busybox.source == "dpkg"
    # Multi-line description is collapsed to its first line.
    assert busybox.description == "Tiny utilities for small and embedded systems"
    assert busybox.db_path == "var/lib/dpkg/status"


def test_dpkg_purl_format(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    busybox = next(c for c in result.components if c.name == "busybox")
    assert busybox.purl() == "pkg:deb/busybox@1.35.0-4?arch=amd64"


# --- opkg -----------------------------------------------------------------


def test_opkg_status_and_control(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "opkg" / "status", _OPKG_STATUS)
    _write(root / "var" / "lib" / "opkg" / "info" / "curl.control", _OPKG_CONTROL_CURL)

    result = sbom.scan(root)
    names = {c.name for c in result.components}
    assert {"dropbear", "uhttpd", "curl"} <= names
    curl = next(c for c in result.components if c.name == "curl")
    assert curl.source == "opkg"
    assert curl.version == "7.88.1-1"
    assert curl.purl() == "pkg:opkg/curl@7.88.1-1?arch=mips_24kc"


def test_opkg_alternate_status_location(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "usr" / "lib" / "opkg" / "status", _OPKG_STATUS)
    result = sbom.scan(root)
    assert any(c.name == "dropbear" for c in result.components)


# --- apk ------------------------------------------------------------------


def test_apk_components_extracted(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "lib" / "apk" / "db" / "installed", _APK_INSTALLED)

    result = sbom.scan(root)
    musl = next(c for c in result.components if c.name == "musl")
    assert musl.version == "1.2.4-r2"
    assert musl.architecture == "x86_64"
    assert musl.license_id == "MIT"
    assert musl.source == "apk"
    assert musl.purl() == "pkg:apk/musl@1.2.4-r2?arch=x86_64"


def test_apk_license_in_cyclonedx(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "lib" / "apk" / "db" / "installed", _APK_INSTALLED)

    result = sbom.scan(root)
    musl = next(c for c in result.components if c.name == "musl")
    cdx = musl.to_cyclonedx()
    assert cdx["licenses"] == [{"license": {"name": "MIT"}}]


# --- multi-manager + dedup ------------------------------------------------


def test_multiple_package_managers_combined(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)
    _write(root / "lib" / "apk" / "db" / "installed", _APK_INSTALLED)

    result = sbom.scan(root)
    sources = {c.source for c in result.components}
    assert sources == {"dpkg", "apk"}


def test_dedup_drops_duplicate_components(tmp_path: Path):
    root = tmp_path / "extract"
    # Same package listed in both opkg status and a .control file.
    _write(root / "var" / "lib" / "opkg" / "status", _OPKG_CONTROL_CURL)
    _write(root / "var" / "lib" / "opkg" / "info" / "curl.control", _OPKG_CONTROL_CURL)

    result = sbom.scan(root)
    curls = [c for c in result.components if c.name == "curl"]
    assert len(curls) == 1


# --- robustness -----------------------------------------------------------


def test_database_found_in_nested_extraction_dir(tmp_path: Path):
    """unblob nests the root filesystem in a subdirectory; the DB is matched by
    its path suffix anywhere under the extract root, not only at the top."""
    root = tmp_path / "extract"
    nested = root / "firmware.bin_extract" / "squashfs-root"
    _write(nested / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    names = {c.name for c in result.components}
    assert "busybox" in names
    busybox = next(c for c in result.components if c.name == "busybox")
    assert busybox.db_path.endswith("var/lib/dpkg/status")


def test_missing_root_returns_empty_sbom(tmp_path: Path):
    result = sbom.scan(tmp_path / "does-not-exist")
    assert result.components == []


def test_no_databases_returns_empty(tmp_path: Path):
    root = tmp_path / "extract"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hostname").write_text("router\n")
    result = sbom.scan(root)
    assert result.components == []


def test_malformed_database_does_not_crash(tmp_path: Path):
    root = tmp_path / "extract"
    _write(
        root / "var" / "lib" / "dpkg" / "status",
        "this is not\na valid\nstatus file\n",
    )
    result = sbom.scan(root)
    assert result.components == []


# --- CycloneDX document ---------------------------------------------------


def test_cyclonedx_document_shape(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    ts = datetime.datetime(2026, 5, 28, tzinfo=datetime.timezone.utc)
    bom = result.to_cyclonedx("router.bin", timestamp=ts)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["version"] == 1
    assert bom["metadata"]["timestamp"] == "2026-05-28T00:00:00+00:00"
    assert bom["metadata"]["component"]["type"] == "firmware"
    assert bom["metadata"]["component"]["name"] == "router.bin"
    tool_names = [
        c["name"] for c in bom["metadata"]["tools"]["components"]
    ]
    assert "embalmer" in tool_names


def test_cyclonedx_component_entries(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    bom = result.to_cyclonedx("router.bin")
    busybox = next(
        c for c in bom["components"] if c["name"] == "busybox"
    )
    assert busybox["type"] == "library"
    assert busybox["version"] == "1.35.0-4"
    assert busybox["purl"] == "pkg:deb/busybox@1.35.0-4?arch=amd64"
    prop_names = {p["name"] for p in busybox["properties"]}
    assert "embalmer:package-manager" in prop_names


def test_to_dict_summary_shape(tmp_path: Path):
    root = tmp_path / "extract"
    _write(root / "var" / "lib" / "dpkg" / "status", _DPKG_STATUS)

    result = sbom.scan(root)
    d = result.to_dict()
    assert d["component_count"] == len(result.components)
    assert d["component_count"] >= 2
    for entry in d["components"]:
        assert entry["name"]
        assert entry["version"]
        assert entry["source"]
        assert entry["purl"]
