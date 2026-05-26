"""Shared pytest fixtures."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SAMPLE_FIRMWARE = FIXTURE_DIR / "sample-firmware.bin"


@pytest.fixture
def sample_firmware() -> Path:
    assert SAMPLE_FIRMWARE.is_file(), "bundled fixture missing"
    return SAMPLE_FIRMWARE


@pytest.fixture
def fake_extracted_tree(tmp_path: Path) -> Path:
    """Build an extracted-filesystem layout on disk that mimics what unblob
    would produce from the bundled squashfs fixture.

    Used by unit tests so the credential scanner and binary finder can run
    without invoking unblob. Mirrors the planted artifacts in REGENERATE.md.
    """
    root = tmp_path / "extract"
    extract = root / "sample-firmware.bin_extract"
    (extract / "etc").mkdir(parents=True)
    (extract / "bin").mkdir(parents=True)
    (extract / "usr" / "lib").mkdir(parents=True)
    (extract / "home" / "admin" / ".ssh").mkdir(parents=True)

    (extract / "etc" / "shadow").write_text(
        "root:$6$saltsalt$3xampleHashedPasswordValue:19000:0:99999:7:::\n"
        "daemon:*:19000:0:99999:7:::\n"
        "admin:$1$abc$0123456789abcdef:19000:0:99999:7:::\n"
    )
    (extract / "etc" / "sample.conf").write_text(
        "admin_password=SuperSecret123\n"
        "api_key=AKIAIOSFODNN7EXAMPLE\n"
        "db_pass=toor\n"
        "host=192.168.0.1\n"
    )
    (extract / "etc" / "network.conf").write_text(
        "hostname=router\ndns=8.8.8.8\n"
    )
    (extract / "home" / "admin" / ".ssh" / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYMATERIAL=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    # ELF placeholders
    (extract / "bin" / "busybox").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 256)
    (extract / "usr" / "lib" / "libcrypto.so").write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128
    )
    (extract / "bin" / "init").write_text("#!/bin/sh\necho boot\n")
    return root


@pytest.fixture
def has_unblob() -> bool:
    return shutil.which("unblob") is not None
