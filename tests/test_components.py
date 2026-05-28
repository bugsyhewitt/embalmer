"""Unit tests for third-party component version detection.

Builds real files on disk carrying genuine component version banners (the same
strings the upstream projects bake into their binaries), then asserts the
scanner recovers the component/version inventory (Article IX: integration-first
— real files over mocks). No external tooling (`strings`, ossuary) is required:
string extraction is in-process and the scan does no CVE lookup.
"""

from __future__ import annotations

from pathlib import Path

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
