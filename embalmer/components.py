"""Third-party component version detection.

Firmware images bundle well-known third-party components — BusyBox, OpenSSL,
curl, Dropbear, the C library — statically or as shared objects. These
components carry their version *as a string baked into the binary* (the same
string `--version` prints at runtime). Recovering those version strings is the
cheap, self-contained first half of the "known-vulnerable component matching"
workflow: once you know the firmware ships ``OpenSSL 1.0.1f``, you know it is
exposed to Heartbleed without running a single symbolic-execution pass.

This module is the version-string *extraction* half. It walks the extracted
tree, reads each file's printable strings (the in-process equivalent of running
``strings`` over it), and matches them against per-component version regexes.
Each match becomes a ``Finding`` with ``category="component"`` so it flows
through the same dedup / summary post-processing pass as every other finding.

The CVE *cross-reference* half — taking ``OpenSSL 1.0.1f`` and resolving it to
CVE-2014-0160 — is intentionally **out of scope here**. That is the ossuary
suite integration (POST_V01 Rank 8); it depends on the ossuary
known-vulnerable-component database and is a separate, future change. Keeping
extraction self-contained means embalmer surfaces the component inventory today
with zero external dependencies, and the ossuary wiring later consumes exactly
the ``component`` findings this module produces.

Design choices mirror the rest of embalmer:

* fast-and-broad, not exhaustive — regexes target the canonical version-banner
  shapes the upstream projects emit, not every conceivable build variant;
* forgiving — an unreadable or oversized file contributes nothing rather than
  aborting the scan;
* dependency-free — printable-string extraction is a few lines of stdlib, so no
  ``strings(1)`` binary or external tool is required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

# Cap per-file reads. Firmware binaries are typically well under this; a
# multi-megabyte blob that is not a component banner carrier is not worth
# scanning byte-by-byte for version strings.
_MAX_READ_BYTES = 16_000_000

# Minimum run of printable bytes to treat as an extracted "string" (matches the
# default of the strings(1) utility).
_MIN_STRING_LEN = 4

# Printable ASCII (plus tab) — the byte set strings(1) considers part of a run.
_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t"
_PRINTABLE_SET = frozenset(_PRINTABLE)


@dataclass(frozen=True)
class ComponentSignature:
    """A recipe for spotting one third-party component's version banner.

    ``pattern`` must expose a named group ``version`` capturing the version
    token. ``cpe_vendor`` / ``cpe_product`` give the CPE coordinates downstream
    consumers (ossuary, NVD) use to resolve the component to CVEs — embalmer
    records them on the finding but does no lookup itself.
    """

    name: str
    pattern: re.Pattern[str]
    cpe_vendor: str
    cpe_product: str


def _sig(name: str, regex: str, vendor: str, product: str) -> ComponentSignature:
    return ComponentSignature(
        name=name,
        pattern=re.compile(regex),
        cpe_vendor=vendor,
        cpe_product=product,
    )


# A small, high-signal catalogue of the components that recur across IoT
# firmware (the same set CveBinarySheet, arXiv:2501.08840, catalogues). Each
# regex targets the canonical version banner the upstream project bakes into its
# binary. Versions look like 1.35.0, 2022.83, 1.0.1f, 7.79.1, 1.2.11, etc., so
# the shared version token allows an optional trailing letter and date-style
# forms.
_VERSION = r"(?P<version>\d+(?:\.\d+){1,3}[a-z]?)"

_SIGNATURES: tuple[ComponentSignature, ...] = (
    # BusyBox prints "BusyBox v1.35.0 (2022-...) multi-call binary."
    _sig("busybox", rf"BusyBox\s+v{_VERSION}", "busybox", "busybox"),
    # OpenSSL banner: "OpenSSL 1.0.1f 6 Jan 2014" / "OpenSSL 3.0.11 ...".
    _sig("openssl", rf"OpenSSL\s+{_VERSION}", "openssl", "openssl"),
    # curl/libcurl: "curl 7.79.1" and "libcurl/7.79.1".
    _sig("curl", rf"(?:lib)?curl[ /]{_VERSION}", "haxx", "curl"),
    # Dropbear SSH: "Dropbear v2022.83" / "dropbear_2022.83".
    _sig(
        "dropbear",
        rf"[Dd]ropbear[ _]?v?{_VERSION}",
        "dropbear_ssh_project",
        "dropbear_ssh",
    ),
    # uClibc: "uClibc 0.9.33" / "uClibc-ng 1.0.40".
    _sig("uclibc", rf"uClibc(?:-ng)?[ -]{_VERSION}", "uclibc", "uclibc"),
    # zlib: "1.2.11" preceded by its banner "inflate 1.2.11 Copyright" /
    # "deflate 1.2.11 Copyright".
    _sig("zlib", rf"(?:in|de)flate\s+{_VERSION}\s+Copyright", "zlib", "zlib"),
    # GNU libc: "GNU C Library ... version 2.31" / "glibc 2.31".
    _sig(
        "glibc",
        rf"(?:GNU C Library.*?version\s+|glibc[ -]){_VERSION}",
        "gnu",
        "glibc",
    ),
    # OpenSSH: "OpenSSH_8.4p1".
    _sig("openssh", rf"OpenSSH_{_VERSION}", "openbsd", "openssh"),
    # Lua: "Lua 5.1.5".
    _sig("lua", rf"Lua\s+{_VERSION}", "lua", "lua"),
    # wpa_supplicant / hostapd: "wpa_supplicant v2.9".
    _sig("wpa_supplicant", rf"wpa_supplicant\s+v?{_VERSION}", "w1.fi", "wpa_supplicant"),
)


def _read_bytes(path: Path) -> bytes | None:
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            return None
        return path.read_bytes()
    except OSError:
        return None


def extract_strings(data: bytes, min_len: int = _MIN_STRING_LEN) -> list[str]:
    """Return printable-ASCII runs of at least ``min_len`` bytes.

    The in-process equivalent of ``strings(1)``: scan ``data`` for maximal runs
    of printable bytes and yield each run that meets the length threshold. Used
    so component detection needs no external ``strings`` binary.
    """
    out: list[str] = []
    run = bytearray()
    for byte in data:
        if byte in _PRINTABLE_SET:
            run.append(byte)
            continue
        if len(run) >= min_len:
            out.append(run.decode("ascii"))
        run.clear()
    if len(run) >= min_len:
        out.append(run.decode("ascii"))
    return out


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _cpe(sig: ComponentSignature, version: str) -> str:
    """A CPE 2.3 URI for the matched component/version.

    The coordinate downstream vulnerability databases (ossuary, NVD) key on.
    embalmer records it; it performs no lookup.
    """
    return f"cpe:2.3:a:{sig.cpe_vendor}:{sig.cpe_product}:{version}:*:*:*:*:*:*:*"


def detect(text_strings: list[str]) -> list[tuple[ComponentSignature, str]]:
    """Match the extracted ``text_strings`` against every component signature.

    Returns ``(signature, version)`` pairs for each distinct component/version
    found, in signature-catalogue order then version order, so output is stable
    regardless of where in the file the banner appeared.
    """
    found: dict[tuple[str, str], tuple[ComponentSignature, str]] = {}
    for s in text_strings:
        for sig in _SIGNATURES:
            match = sig.pattern.search(s)
            if match:
                version = match.group("version")
                found.setdefault((sig.name, version), (sig, version))
    return [found[k] for k in sorted(found)]


def scan(extract_root: str | Path) -> list[Finding]:
    """Scan the extracted tree under ``extract_root`` for component versions.

    Walks every regular file once, extracts its printable strings, and matches
    them against the component catalogue. Each distinct component/version found
    in a file becomes one ``Finding`` (``category="component"``); the same
    component/version in many files dedups downstream via the post-processing
    pass (its ``cpe`` is the identity discriminator). Severity is ``info`` —
    the *presence* of a component is not itself a vulnerability; exploitability
    is determined later by CVE cross-reference (ossuary, out of scope here).
    """
    root = Path(extract_root)
    findings: list[Finding] = []

    if not root.exists():
        return findings

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        data = _read_bytes(path)
        if data is None:
            continue
        strings = extract_strings(data)
        if not strings:
            continue
        rel = _rel(path, root)
        for sig, version in detect(strings):
            findings.append(
                Finding(
                    category="component",
                    path=rel,
                    type=sig.name,
                    detail=f"{sig.name} {version}",
                    severity="info",
                    extra={
                        "component": sig.name,
                        "version": version,
                        "cpe": _cpe(sig, version),
                    },
                )
            )

    return findings
