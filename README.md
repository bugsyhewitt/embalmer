# embalmer

**A firmware analysis pipeline that orchestrates extraction, filesystem
inspection, credential scanning, and binary analysis into a single structured
firmware audit report.**

embalmer is the orchestration layer of the necromancer suite for firmware
reverse engineering. It does **not** reimplement extraction or binary analysis.
It composes existing, best-in-class tools:

```
firmware image
      │
      ▼
  extract  ──►  unblob  (recursive extraction of 30+ formats)
      │
      ▼
 inspect filesystem  ──►  credential / key / config scan
      │                └──►  X.509 certificate / TLS config scan
      │
      ▼
 binary analysis  ──►  blight   (pattern-based CWE detection — fast, broad)
              └──►  autopsy  (angr symbolic execution — deep, flow-sensitive)
      │
      ▼
 package inventory  ──►  SBOM  (CycloneDX 1.6 JSON from dpkg/opkg/apk databases)
      │
      ▼
  structured firmware audit report  (JSON or markdown)
```

The gap embalmer fills is **pipeline orchestration** — `extract → analyze →
report` — rather than extraction itself. `binwalk` and `unblob` are mature
extractors; embalmer wraps `unblob` and turns a raw firmware blob into a single
combined audit artifact.

---

## Install

embalmer requires **Python 3.13+**.

```sh
git clone https://github.com/bugsyhewitt/embalmer
cd embalmer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This pulls in `unblob`, `python-magic`, and `cryptography` from PyPI
(`cryptography` is pure-Python from embalmer's perspective and powers the
`certs` check). `unblob` itself requires
several **system-level** packages for its extractors — see
**[System dependencies for unblob](#system-dependencies-for-unblob)** below.

Verify the install:

```sh
embalmer --help
embalmer --version
```

---

## Usage

```
embalmer --firmware FIRMWARE [--workdir DIR]
         [--checks {extract,creds,certs,binaries,sbom,all}]
         [--analyzer {blight,autopsy,both}]
         [--format {json,md}]
         [--blight-binary PATH] [--autopsy-binary PATH]
         [--output FILE]
```

| Flag | Default | Description |
|---|---|---|
| `--firmware` | *(required)* | Path to the firmware image (raw blob, ZIP, tarball, vendor format). |
| `--workdir` | `./embalmer-work/` | Directory unblob extracts into. |
| `--checks` | `all` | Which checks to run: `extract`, `creds`, `certs`, `binaries`, `sbom`, or `all`. |
| `--analyzer` | `blight` | Binary analyzer for the `binaries` check: `blight`, `autopsy`, or `both`. |
| `--format` | `json` | Report format: `json` or `md`. |
| `--blight-binary` | `blight` | Path to the blight executable for the binary-analysis handoff. |
| `--autopsy-binary` | `autopsy` | Path to the autopsy executable (used when `--analyzer` is `autopsy` or `both`). |
| `--output`, `-o` | *(stdout)* | Write the report to a file instead of stdout. |

### Checks

- **`extract`** — recursively extract the firmware via unblob and emit the
  extraction tree, file count, and extraction time.
- **`creds`** — walk the extracted filesystem for password hashes
  (`/etc/shadow`-style), hardcoded credentials in config files
  (`password=`, `api_key=`, `db_pass=`, …), and private keys (PEM blocks and
  well-known key filenames).
- **`certs`** — walk the extracted filesystem for X.509 certificate files
  (`.crt`, `.pem`, `.cer`, `.der`, or any filename containing `certificate`),
  parse them with the `cryptography` library, and flag risky TLS configuration:
  - **expired** certificates (`NotAfter` is in the past) — **HIGH**
  - **self-signed** certificates (issuer == subject) — **MEDIUM**
  - **weak algorithms / undersized keys**: MD5 or SHA-1 signature algorithms,
    RSA keys < 2048 bits, EC keys < 224 bits — **MEDIUM**
  - **wildcard** certificates (CN or SubjectAltName contains `*`) — **INFO**

  Each finding carries the certificate's subject CN, issuer CN, expiry date,
  and a human-readable reason string. A single certificate can produce several
  findings (e.g. an expired self-signed wildcard cert emits three).
- **`binaries`** — locate ELF binaries in the extracted tree and hand each off
  to a binary analyzer (selected with `--analyzer`), aggregating the analyzer's
  CWE findings into the report.
- **`sbom`** — walk the extracted filesystem's package-manager databases and
  emit a **CycloneDX 1.6** (ECMA-424) JSON Software Bill of Materials of every
  installed package. Three package-manager families are inventoried:
  - **dpkg** (Debian/Ubuntu) — `…/var/lib/dpkg/status`
  - **opkg** (OpenWrt) — `…/var/lib/opkg/status`, the alternate
    `usr/lib/opkg/status` and `etc/opkg/status` locations, and per-package
    `…/var/lib/opkg/info/*.control` files
  - **apk** (Alpine) — `…/lib/apk/db/installed`

  Databases are matched by their conventional path *suffix* anywhere under the
  extract root, so nested root filesystems (the usual unblob layout) are found.
  Each package becomes a CycloneDX `component` carrying a
  [Package URL (purl)](https://github.com/package-url/purl-spec) — e.g.
  `pkg:deb/busybox@1.35.0-4?arch=amd64` — which downstream tools
  (Dependency-Track, grype, trivy) use to match against vulnerability
  databases. Only packages marked installed are included; removed/config-only
  dpkg and opkg entries are skipped. See the report shape below for the JSON
  layout.
- **`all`** — run all five and produce a combined report.

`creds`, `certs`, `binaries`, and `sbom` all depend on extraction, so
extraction always runs when they are requested (its output appears in the
report only if `extract` or `all` was selected).

### Finding deduplication, grouping, and the summary

After every check runs, embalmer applies a single post-processing pass before
rendering the report:

- **Deduplication.** Real firmware images carry thousands of symlinks and
  duplicate files spread across squashfs partitions, so the same secret or CWE
  often appears at dozens of paths. embalmer collapses findings that are
  semantically identical — same category, type, severity, and underlying
  artifact (e.g. the same config key, the same shadow hash, or the same
  CWE/function pair) — into a **single** finding. The survivor gains a `count`
  (how many raw occurrences collapsed) and a sorted `paths` list of every path
  it was seen at. A finding seen only once still reports `count: 1` and a
  single-entry `paths` list, so consumers never special-case the singleton. A
  firmware with 50 symlinked copies of `/etc/shadow` now emits **one** credential
  finding with `count: 50`, not 50 identical rows.
- **Per-binary grouping.** Binary findings are additionally clustered by the
  binary they came from, surfaced under the top-level `binary_groups` key
  alongside the flat `binaries` list, so an analyst can read the report
  per-binary as well as per-finding.
- **Summary block.** A top-level `summary` object reports the total finding
  count broken down `by_severity` (in `critical → high → medium → low → info`
  order; unknown labels bucket under `other`) and `by_category`. It is the first
  thing the markdown report renders and the first thing an analyst reads. The
  summary counts **distinct** findings (post-dedup), which is what you triage.

The summary only appears when at least one finding-bearing check
(`creds`/`certs`/`binaries`) ran; an extract-only report has no `summary`.

### Choosing a binary analyzer (`--analyzer`)

The `binaries` check hands each discovered ELF off to one or more analyzers from
the necromancer suite. Both are external tools embalmer shells out to (it does
not import them, so neither becomes an embalmer dependency):

- **`blight`** *(default)* — a fast, radare2-backed pattern matcher. Broad
  coverage, runs quickly over every binary. The default for backwards
  compatibility; if you do not pass `--analyzer`, embalmer behaves exactly as
  before.
- **`autopsy`** — an angr-backed symbolic-execution engine. Slower and deeper:
  it recovers control flow and reasons about whole-program data flow to surface
  flow-sensitive CWE classes (e.g. attacker-controlled buffer offsets, use
  after free) that pattern matching misses. Best aimed at a handful of
  suspicious binaries. Requires **Python 3.13+** (angr).
- **`both`** — run blight *and* autopsy over every ELF and aggregate all
  findings. Use this for the most thorough pass.

embalmer normalizes each analyzer's native JSON output into the unified
`Finding` shape, so blight and autopsy findings appear side by side under the
report's `binaries` array regardless of which tool produced them.

```sh
# fast, broad scan (default)
embalmer --firmware router.bin --checks binaries

# deep symbolic analysis with autopsy
embalmer --firmware router.bin --checks binaries --analyzer autopsy \
         --autopsy-binary /opt/necromancer/bin/autopsy

# run both analyzers and aggregate
embalmer --firmware router.bin --checks binaries --analyzer both
```

### Example workflow

Full audit of a router firmware image:

```sh
embalmer --firmware router.bin --checks all
```

JSON report to a file, extraction only:

```sh
embalmer --firmware router.bin --workdir ./work --checks extract -o report.json
```

Generate a CycloneDX SBOM of the firmware's installed packages:

```sh
embalmer --firmware router.bin --checks sbom -o sbom-report.json
# the standalone CycloneDX document lives at .sbom.bom in the JSON output
```

Markdown summary with a specific blight binary:

```sh
embalmer --firmware router.bin --checks all --format md \
         --blight-binary /opt/necromancer/bin/blight -o audit.md
```

### Report shape (JSON)

```json
{
  "firmware": "router.bin",
  "checks": ["extract", "creds", "certs", "binaries"],
  "summary": {
    "total": 3,
    "by_severity": { "high": 2, "medium": 1 },
    "by_category": { "binary": 1, "certificate": 1, "credential": 1 }
  },
  "extraction": {
    "extraction_tree": { "...": "..." },
    "file_count": 1423,
    "extraction_time_ms": 8120,
    "extract_root": "./embalmer-work/"
  },
  "credentials": [
    {
      "category": "credential", "path": "etc/shadow", "type": "password_hash",
      "severity": "high", "detail": "...",
      "count": 50, "paths": ["rootfs/etc/shadow", "..."]
    }
  ],
  "certificates": [
    {
      "category": "certificate", "path": "etc/ssl/device.crt", "type": "expired_cert",
      "severity": "high", "detail": "certificate expired on 2021-03-04",
      "subject_cn": "device.local", "issuer_cn": "device.local",
      "expiry": "2021-03-04", "reason": "certificate expired on 2021-03-04",
      "count": 1, "paths": ["etc/ssl/device.crt"]
    }
  ],
  "binaries": [
    {
      "category": "binary", "path": "bin/busybox", "type": "CWE-120",
      "severity": "high", "detail": "...", "count": 1, "paths": ["bin/busybox"]
    }
  ],
  "binary_groups": [
    { "path": "bin/busybox", "finding_count": 1, "findings": [ { "...": "..." } ] }
  ],
  "sbom": {
    "component_count": 2,
    "components": [
      {
        "name": "busybox", "version": "1.35.0-4", "source": "dpkg",
        "architecture": "amd64", "purl": "pkg:deb/busybox@1.35.0-4?arch=amd64",
        "db_path": "squashfs-root/var/lib/dpkg/status"
      }
    ],
    "bom": {
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": {
        "timestamp": "2026-05-28T00:00:00+00:00",
        "tools": { "components": [ { "type": "application", "name": "embalmer", "group": "necromancer" } ] },
        "component": { "type": "firmware", "name": "router.bin" }
      },
      "components": [
        { "type": "library", "name": "busybox", "version": "1.35.0-4",
          "purl": "pkg:deb/busybox@1.35.0-4?arch=amd64", "properties": [ ... ] }
      ]
    }
  }
}
```

The `sbom.bom` object is a complete, standalone **CycloneDX 1.6** document —
copy it straight out of the report and feed it to any CycloneDX-aware consumer.
`sbom.components` is a flat convenience summary of the same packages.

---

## System dependencies for unblob

embalmer delegates all extraction to **unblob**. unblob's `pip install` pulls
Python packages such as `ubi_reader`, `jefferson`, and `lzallright` (a Rust
extension), and at runtime it shells out to a number of **system binaries** for
the various firmware formats. Without these, extraction of the corresponding
format will fail.

> **Read unblob's official installation guide:**
> <https://unblob.org/installation/>
> It documents the full, current set of extractor dependencies and is the
> authoritative source. The lists below are a convenience snapshot.

Of particular note for firmware work: **squashfs** (the most common firmware
root filesystem) is extracted by unblob using **`sasquatch`**, ReFirmLabs'
patched `unsquashfs`. Plain `squashfs-tools` is **not** sufficient for all
squashfs variants unblob handles — install `sasquatch`.

### Arch Linux

```sh
# core extractors
sudo pacman -S --needed \
    p7zip zstd lz4 lzo lzop unar \
    e2fsprogs squashfs-tools cpio

# sasquatch (squashfs) is in the AUR
yay -S sasquatch          # or: paru -S sasquatch
```

`ubi_reader`, `jefferson`, and `lzallright` are installed automatically by
`pip install -e .` (they ship as Python wheels / build from source).

### Debian / Ubuntu

```sh
sudo apt update
sudo apt install -y \
    p7zip-full zstd lz4 liblzo2-dev lzop unar \
    e2fsprogs squashfs-tools cpio \
    build-essential pkg-config
```

`sasquatch` is not packaged for Debian; build it from ReFirmLabs' source per
unblob's installation guide, or use unblob's official Docker image which
bundles every extractor.

### Verifying your extractor set

unblob can report which external extractors it can find:

```sh
unblob --show-external-dependencies
```

Anything marked missing (`✗`) means firmware using that format will not extract.

---

## Bundled test fixture

A small (< 5 MB) crafted **squashfs** image lives at
`tests/fixtures/sample-firmware.bin`. It contains deliberately planted artifacts
(fake credentials in `/etc/shadow` and `/etc/sample.conf`, a fake private key,
placeholder ELF binaries) so the smoke and integration tests have known content
to find. The source assets and build script (`mksquashfs` commands) are
documented in [`tests/fixtures/REGENERATE.md`](tests/fixtures/REGENERATE.md).

---

## Development & tests

```sh
pip install -e ".[dev]"

# unit + smoke tests only (no external tools required — unblob/blight mocked)
pytest -m "not integration"

# everything, including real unblob extraction (requires unblob + extractors)
pytest
```

The unblob, blight, and autopsy boundaries are mocked in the unit/smoke tests,
so the core suite runs in any environment — in particular, autopsy's tests never
import angr. The `@pytest.mark.integration` tests exercise real unblob extraction
of the bundled fixture plus real subprocess handoffs to stub blight and autopsy
executables (so the subprocess path is covered without building either tool).

---

## Scope (v0.1)

embalmer v0.1 is intentionally narrow. It does **not** include:

- Vendor-specific firmware formats beyond what unblob covers natively
- Live firmware download from vendor sites
- A web dashboard
- Diff mode (comparing two firmware versions)
- Emulation (running extracted binaries under QEMU)
- A second extraction backend (unblob only — a binwalk fallback is planned for
  v0.2)

For the ranked list of post-v0.1 improvements with rationale and effort
estimates, see [`POST_V01.md`](POST_V01.md).

---

## Ethical use

embalmer is a defensive and research tool. **Only analyze firmware you own or
are explicitly authorized to assess.** Extracting, analyzing, or redistributing
firmware may be restricted by copyright, licensing, export-control, or
computer-misuse law in your jurisdiction. You are responsible for ensuring your
use is lawful and authorized. The authors accept no liability for misuse.

---

## Attribution

See [`NOTICE`](NOTICE). embalmer's design is inspired by the original
**firmeye** project; recursive extraction is performed by **unblob** (ONEKEY).
Licensed under the MIT License (see [`LICENSE`](LICENSE)).
