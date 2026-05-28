"""Unit tests for live firmware acquisition via graverobber (POST_V01 Rank 10).

The graverobber subprocess boundary (``fetch._run_graverobber``) is mocked, so
these run without graverobber installed — mirroring how extract's unblob/binwalk
seams and the binaries SubprocessAnalyzer seams are tested. A separate
``@pytest.mark.integration`` test exercises the real subprocess path against a
stub graverobber executable.
"""

from __future__ import annotations

import os
import stat

import pytest

from embalmer import fetch
from embalmer.fetch import FetchError


def test_fetch_returns_local_path(tmp_path, monkeypatch):
    out = tmp_path / "fw" / "image.bin"

    def fake_run(url, output, gr_bin):
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"\x00FIRMWARE\x00")

    monkeypatch.setattr(fetch, "_run_graverobber", fake_run)

    result = fetch.fetch("https://vendor.example/fw.bin", out)
    assert result == out
    assert result.is_file()
    assert result.read_bytes() == b"\x00FIRMWARE\x00"


def test_fetch_empty_url_raises(tmp_path):
    with pytest.raises(FetchError, match="non-empty"):
        fetch.fetch("", tmp_path / "fw.bin")
    with pytest.raises(FetchError, match="non-empty"):
        fetch.fetch("   ", tmp_path / "fw.bin")


def test_fetch_missing_output_after_success_raises(tmp_path, monkeypatch):
    """graverobber exits 0 but writes nothing -> we must not pretend success."""
    out = tmp_path / "image.bin"
    monkeypatch.setattr(fetch, "_run_graverobber", lambda url, output, gr_bin: None)
    with pytest.raises(FetchError, match="no firmware file was written"):
        fetch.fetch("https://vendor.example/fw.bin", out)


def test_run_graverobber_missing_binary_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch.shutil, "which", lambda _b: None)
    with pytest.raises(FetchError, match="not found on PATH"):
        fetch._run_graverobber("https://x", tmp_path / "fw.bin", "graverobber")


def test_run_graverobber_nonzero_exit_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch.shutil, "which", lambda _b: "/usr/bin/graverobber")

    class FakeProc:
        returncode = 7
        stderr = "404 Not Found"

    monkeypatch.setattr(fetch.subprocess, "run", lambda *a, **k: FakeProc())
    with pytest.raises(FetchError, match="exited 7"):
        fetch._run_graverobber("https://x", tmp_path / "fw.bin", "graverobber")


def test_run_graverobber_builds_expected_command(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch.shutil, "which", lambda _b: "/usr/bin/graverobber")
    captured = {}

    class FakeProc:
        returncode = 0
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(fetch.subprocess, "run", fake_run)
    out = tmp_path / "nested" / "fw.bin"
    fetch._run_graverobber("https://vendor/fw", out, "graverobber")

    assert captured["cmd"] == [
        "graverobber",
        "fetch",
        "--url",
        "https://vendor/fw",
        "--output",
        str(out),
    ]
    # parent dir is created so graverobber can write there
    assert out.parent.is_dir()


def test_fetch_respects_custom_binary(tmp_path, monkeypatch):
    seen = {}

    def fake_run(url, output, gr_bin):
        seen["bin"] = gr_bin
        output.write_bytes(b"x")

    monkeypatch.setattr(fetch, "_run_graverobber", fake_run)
    fetch.fetch("https://x", tmp_path / "fw.bin", graverobber_binary="/opt/gr")
    assert seen["bin"] == "/opt/gr"


@pytest.mark.integration
def test_fetch_real_subprocess_stub(tmp_path):
    """Exercise the real subprocess path against a stub graverobber script."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "graverobber"
    # The stub parses --output and writes a fake firmware blob there.
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "out = args[args.index('--output') + 1]\n"
        "open(out, 'wb').write(b'STUBFW')\n"
        "sys.exit(0)\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{stub_dir}{os.pathsep}{old_path}"
    try:
        out = tmp_path / "downloaded.bin"
        result = fetch.fetch("https://vendor.example/fw.bin", out)
        assert result.read_bytes() == b"STUBFW"
    finally:
        os.environ["PATH"] = old_path
