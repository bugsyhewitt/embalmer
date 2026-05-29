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


# A high-signal catalogue of the components that recur across IoT firmware (the
# same families CveBinarySheet, arXiv:2501.08840, catalogues). Each regex
# targets the canonical version banner the upstream project bakes into its
# binary. Versions look like 1.35.0, 2022.83, 1.0.1f, 7.79.1, 1.2.11, etc., so
# the shared version token allows an optional trailing letter and date-style
# forms. Every signature anchors on a component-specific banner prefix (never a
# bare version number) to keep the catalogue false-positive-free as it widens.
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
    # --- Wider catalogue (Phase 2): the next tier of components that recur ---
    # across IoT firmware, each with a distinctive canonical version banner so
    # the regex stays high-signal (no bare-number false positives).
    # lighttpd: "lighttpd/1.4.55" — Server: header and --version banner. A
    # recurring source of embedded-webserver CVEs.
    _sig("lighttpd", rf"lighttpd/{_VERSION}", "lighttpd", "lighttpd"),
    # dnsmasq: "Dnsmasq version 2.80" — DNS/DHCP, the DNSpooq CVE cluster.
    _sig("dnsmasq", rf"[Dd]nsmasq version {_VERSION}", "thekelleys", "dnsmasq"),
    # mosquitto: "mosquitto version 2.0.11" — the canonical MQTT broker.
    _sig("mosquitto", rf"mosquitto version {_VERSION}", "eclipse", "mosquitto"),
    # Portable SDK for UPnP / pupnp / libupnp: "Portable SDK for UPnP
    # devices/1.6.18" — the CallStranger (CVE-2020-12695) component.
    _sig(
        "libupnp",
        rf"Portable SDK for UPnP devices?/{_VERSION}",
        "pupnp_project",
        "pupnp",
    ),
    # expat: "expat_2.2.6" / "expat-2.2.6" — the XML parser bundled widely;
    # recurring billion-laughs / integer-overflow CVEs.
    _sig("expat", rf"expat[_-]{_VERSION}", "libexpat_project", "libexpat"),
    # libpng: "libpng version 1.6.37" — the PNG decoder, recurring CVEs.
    _sig("libpng", rf"libpng version {_VERSION}", "libpng", "libpng"),
    # GNU bash: "bash, version 5.0.17" / "Bash version 5.0" (Shellshock).
    _sig("bash", rf"[Bb]ash,? version {_VERSION}", "gnu", "bash"),
    # libpcap / tcpdump: "libpcap version 1.9.1" / "tcpdump version 4.9.3".
    _sig("libpcap", rf"libpcap version {_VERSION}", "tcpdump", "libpcap"),
    _sig("tcpdump", rf"tcpdump version {_VERSION}", "tcpdump", "tcpdump"),
    # --- Wider catalogue, tier 3 (Phase 2, Rotation 16): the next tier of ---
    # components that recur across IoT firmware. Each anchors on a distinctive
    # canonical banner (never a bare version number) so the catalogue stays
    # false-positive-free as it widens; the ossuary cross-reference (Rank 8,
    # still open) consumes the wider inventory unchanged.
    # U-Boot bootloader: "U-Boot 2021.01 (Jan 12 2021 - ...)" — present on
    # nearly every embedded Linux device; a recurring source of secure-boot CVEs.
    _sig("u-boot", rf"U-Boot {_VERSION}", "denx", "u-boot"),
    # Linux kernel: "Linux version 4.14.180 (builder@host) ..." — the kernel
    # banner baked into the image; the single most important version to inventory.
    _sig("linux_kernel", rf"Linux version {_VERSION}", "linux", "linux_kernel"),
    # Mbed TLS (formerly PolarSSL): "Mbed TLS 2.16.0" / "mbed TLS 2.16.0" — the
    # embedded TLS stack favoured on constrained IoT devices.
    _sig("mbedtls", rf"[Mm]bed TLS {_VERSION}", "arm", "mbed_tls"),
    # GnuTLS: "GnuTLS 3.6.15" — the GNU TLS library, an OpenSSL alternative.
    _sig("gnutls", rf"GnuTLS {_VERSION}", "gnu", "gnutls"),
    # SQLite: "SQLite version 3.31.1" (sqlite3 CLI / shell banner) — the
    # ubiquitous embedded database.
    _sig("sqlite", rf"SQLite version {_VERSION}", "sqlite", "sqlite"),
    # PCRE / PCRE2: "PCRE 8.44" / "PCRE2 10.34" — the regex library bundled
    # widely; recurring buffer-overflow CVEs.
    _sig("pcre", rf"PCRE2? {_VERSION}", "pcre", "pcre"),
    # ncurses: "ncurses 6.2.20200212" — the terminal/TUI library.
    _sig("ncurses", rf"ncurses {_VERSION}", "gnu", "ncurses"),
    # libssh2: "libssh2/1.9.0" — the client-side SSH library (distinct from
    # Dropbear/OpenSSH); recurring CVEs and frequently statically linked.
    _sig("libssh2", rf"libssh2/{_VERSION}", "libssh2", "libssh2"),
    # GNU Wget: "GNU Wget 1.20.3" / "Wget/1.20.3" — common firmware HTTP client.
    _sig("wget", rf"(?:GNU )?Wget[ /]{_VERSION}", "gnu", "wget"),
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
                        # The CPE vendor is the component's upstream supplier —
                        # the one party embalmer CAN assert for a binary-detected
                        # component (it is the project that ships the library).
                        # Carried so the SBOM cross-link can populate the
                        # supplier field NTIA requires.
                        "vendor": sig.cpe_vendor,
                    },
                )
            )

    return findings
