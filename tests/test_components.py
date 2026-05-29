"""Unit tests for third-party component version detection.

Builds real files on disk carrying genuine component version banners (the same
strings the upstream projects bake into their binaries), then asserts the
scanner recovers the component/version inventory (Article IX: integration-first
— real files over mocks). No external tooling (`strings`, ossuary) is required:
string extraction is in-process and the scan does no CVE lookup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from embalmer import components
from embalmer.models import Report
from embalmer.summary import postprocess


# --- realistic binary-banner fixtures -------------------------------------
# Version strings as they appear, embedded in NUL-padded blobs to mimic an ELF
# (so the test also exercises printable-run extraction across NUL boundaries).


def _blob(*banners: str) -> bytes:
    chunks = [b"\x7fELF\x02\x01\x01\x00"]
    for b in banners:
        chunks.append(b"\x00\x00")
        chunks.append(b.encode("ascii"))
        chunks.append(b"\x00\x00")
    return b"".join(chunks)


def _write_tree(tmp_path: Path) -> Path:
    root = tmp_path / "extract"
    (root / "bin").mkdir(parents=True)
    (root / "usr" / "lib").mkdir(parents=True)
    (root / "usr" / "sbin").mkdir(parents=True)

    (root / "bin" / "busybox").write_bytes(
        _blob("BusyBox v1.35.0 (2022-08-01 12:00:00 UTC) multi-call binary.")
    )
    (root / "usr" / "lib" / "libcrypto.so").write_bytes(
        _blob("OpenSSL 1.0.1f 6 Jan 2014")
    )
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "bin" / "curl").write_bytes(
        _blob("curl 7.79.1 (x86_64-pc-linux-gnu) libcurl/7.79.1")
    )
    (root / "usr" / "sbin" / "dropbear").write_bytes(
        _blob("Dropbear v2022.83")
    )
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "libc.so").write_bytes(
        _blob("inflate 1.2.11 Copyright 1995-2017 Mark Adler ")
    )
    return root


def test_extract_strings_basic():
    data = b"\x00\x00hello\x00\x01world!!\x00ab"
    out = components.extract_strings(data, min_len=4)
    assert "hello" in out
    assert "world!!" in out
    # "ab" is shorter than min_len and must be dropped.
    assert "ab" not in out


def test_detects_busybox(tmp_path):
    root = _write_tree(tmp_path)
    findings = components.scan(root)
    bb = [f for f in findings if f.extra["component"] == "busybox"]
    assert bb, "expected a busybox component finding"
    assert bb[0].extra["version"] == "1.35.0"
    assert bb[0].category == "component"
    assert "bin/busybox" in bb[0].path


def test_detects_openssl_with_letter_version(tmp_path):
    root = _write_tree(tmp_path)
    findings = components.scan(root)
    ssl = [f for f in findings if f.extra["component"] == "openssl"]
    assert ssl, "expected an openssl finding"
    # The trailing letter (1.0.1f) must be captured — that is the Heartbleed
    # version and distinguishing it from 1.0.1g is the whole point.
    assert ssl[0].extra["version"] == "1.0.1f"


def test_detects_curl_dropbear_zlib(tmp_path):
    root = _write_tree(tmp_path)
    found = {f.extra["component"]: f.extra["version"] for f in components.scan(root)}
    assert found.get("curl") == "7.79.1"
    assert found.get("dropbear") == "2022.83"
    assert found.get("zlib") == "1.2.11"


# --- wider catalogue (Phase 2) -------------------------------------------
# Each entry is (banner string as baked into a real binary, expected component
# name, expected version). The banners are the canonical --version/Server
# strings the upstream projects emit.
_WIDER_CATALOGUE = [
    ("lighttpd/1.4.55", "lighttpd", "1.4.55"),
    ("Dnsmasq version 2.80 Copyright (c) 2000-2018", "dnsmasq", "2.80"),
    ("mosquitto version 2.0.11 starting", "mosquitto", "2.0.11"),
    ("Portable SDK for UPnP devices/1.6.18", "libupnp", "1.6.18"),
    ("expat_2.2.6", "expat", "2.2.6"),
    ("libpng version 1.6.37 - April 14, 2019", "libpng", "1.6.37"),
    ("bash, version 5.0.17(1)-release", "bash", "5.0.17"),
    ("libpcap version 1.9.1 (with TPACKET_V3)", "libpcap", "1.9.1"),
    ("tcpdump version 4.9.3", "tcpdump", "4.9.3"),
    # tier 3 (Rotation 16)
    ("U-Boot 2021.01 (Jan 12 2021 - 00:00:00 +0000)", "u-boot", "2021.01"),
    ("Linux version 4.14.180 (builder@host) (gcc ...) #1 SMP", "linux_kernel", "4.14.180"),
    ("Mbed TLS 2.16.0", "mbedtls", "2.16.0"),
    ("mbed TLS 2.16.0", "mbedtls", "2.16.0"),
    ("GnuTLS 3.6.15", "gnutls", "3.6.15"),
    ("SQLite version 3.31.1 2020-01-27 19:55:54", "sqlite", "3.31.1"),
    ("PCRE 8.44 2020-02-12", "pcre", "8.44"),
    ("PCRE2 10.34 2019-11-21", "pcre", "10.34"),
    ("ncurses 6.2.20200212", "ncurses", "6.2.20200212"),
    ("libssh2/1.9.0", "libssh2", "1.9.0"),
    ("GNU Wget 1.20.3 built on linux-gnu.", "wget", "1.20.3"),
    ("Wget/1.20.3", "wget", "1.20.3"),
]


@pytest.mark.parametrize("banner,name,version", _WIDER_CATALOGUE)
def test_wider_catalogue_detects_component(tmp_path, banner, name, version):
    root = tmp_path / "extract"
    root.mkdir()
    (root / "binfile").write_bytes(_blob(banner))
    findings = components.scan(root)
    hits = [f for f in findings if f.extra["component"] == name]
    assert hits, f"expected a {name} finding for banner {banner!r}"
    assert hits[0].extra["version"] == version
    assert hits[0].category == "component"
    assert hits[0].severity == "info"


def test_wider_catalogue_cpe_coordinates(tmp_path):
    # CPE vendor/product coordinates are what ossuary/NVD key on later; lock the
    # coordinates for a representative new component (CallStranger's libupnp).
    root = tmp_path / "extract"
    root.mkdir()
    (root / "upnp").write_bytes(_blob("Portable SDK for UPnP devices/1.6.18"))
    findings = components.scan(root)
    upnp = next(f for f in findings if f.extra["component"] == "libupnp")
    assert upnp.extra["cpe"] == "cpe:2.3:a:pupnp_project:pupnp:1.6.18:*:*:*:*:*:*:*"


def test_wider_catalogue_no_false_positive_on_prose(tmp_path):
    # The new signatures must anchor on a real banner prefix, not bare numbers.
    root = tmp_path / "extract"
    root.mkdir()
    (root / "notes.txt").write_text(
        "We deployed lighttpd and dnsmasq and mosquitto on the device in 2019. "
        "Versions are documented elsewhere (e.g. 1.4.55, 2.80, 2.0.11) but "
        "without a recognized banner they must not be flagged.\n"
    )
    assert components.scan(root) == []


def test_tier3_cpe_coordinates(tmp_path):
    # Lock the CPE vendor/product coordinates for representative tier-3 entries —
    # these are what ossuary/NVD key on later. U-Boot and the Linux kernel are
    # the two most important new inventory items.
    root = tmp_path / "extract"
    root.mkdir()
    (root / "uboot").write_bytes(_blob("U-Boot 2021.01 (Jan 12 2021 - ...)"))
    (root / "vmlinux").write_bytes(_blob("Linux version 4.14.180 (builder@host)"))
    found = {f.extra["component"]: f.extra["cpe"] for f in components.scan(root)}
    assert found["u-boot"] == "cpe:2.3:a:denx:u-boot:2021.01:*:*:*:*:*:*:*"
    assert (
        found["linux_kernel"]
        == "cpe:2.3:a:linux:linux_kernel:4.14.180:*:*:*:*:*:*:*"
    )


def test_tier3_no_false_positive_on_prose(tmp_path):
    # Tier-3 names appearing in prose without their banner must not be flagged.
    root = tmp_path / "extract"
    root.mkdir()
    (root / "notes.txt").write_text(
        "The image bundles u-boot, sqlite, gnutls and mbedtls. We run wget and "
        "rely on pcre. Versions like 2021.01, 3.31.1 and 1.9.0 are noted in the "
        "changelog but carry no recognized banner here.\n"
    )
    assert components.scan(root) == []


def test_finding_carries_cpe(tmp_path):
    root = _write_tree(tmp_path)
    findings = components.scan(root)
    ssl = next(f for f in findings if f.extra["component"] == "openssl")
    assert ssl.extra["cpe"] == "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*"


def test_severity_is_info(tmp_path):
    # Presence of a component is not itself a vulnerability — exploitability is
    # decided later by CVE cross-reference (ossuary, out of scope).
    root = _write_tree(tmp_path)
    findings = components.scan(root)
    assert findings
    assert all(f.severity == "info" for f in findings)


def test_no_false_positive_on_benign_text(tmp_path):
    root = tmp_path / "extract"
    root.mkdir()
    (root / "readme.txt").write_text(
        "This firmware was built in 2024. Version numbers like 1.2.3 alone "
        "must not be flagged without a recognized component banner.\n"
    )
    assert components.scan(root) == []


def test_same_version_in_two_files_dedups_via_postprocess(tmp_path):
    root = tmp_path / "extract"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir(parents=True)
    (root / "a" / "busybox").write_bytes(_blob("BusyBox v1.35.0 multi-call binary."))
    (root / "b" / "busybox").write_bytes(_blob("BusyBox v1.35.0 multi-call binary."))

    findings = components.scan(root)
    assert len(findings) == 2  # raw: one per file

    report = Report(firmware="fw.bin", checks=["components"], components=findings)
    postprocess(report)
    # After dedup the two identical busybox findings collapse to one with count 2.
    bb = [f for f in report.components if f.extra["component"] == "busybox"]
    assert len(bb) == 1
    assert bb[0].extra["count"] == 2
    assert len(bb[0].extra["paths"]) == 2


def test_scan_missing_root_returns_empty(tmp_path):
    assert components.scan(tmp_path / "does-not-exist") == []


def test_oversized_file_skipped(tmp_path, monkeypatch):
    root = tmp_path / "extract"
    root.mkdir()
    (root / "huge").write_bytes(_blob("BusyBox v1.35.0 multi-call binary."))
    monkeypatch.setattr(components, "_MAX_READ_BYTES", 4)
    assert components.scan(root) == []


def test_symlinks_not_followed(tmp_path):
    root = tmp_path / "extract"
    root.mkdir()
    real = root / "busybox"
    real.write_bytes(_blob("BusyBox v1.35.0 multi-call binary."))
    link = root / "sh"
    link.symlink_to(real)
    findings = components.scan(root)
    # Only the real file is scanned; the symlink is skipped (the real finding's
    # dedup superset is handled by the post-process pass, not by re-scanning).
    paths = {f.path for f in findings}
    assert "busybox" in paths
    assert "sh" not in paths
