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
      │
      ▼
 binary analysis  ──►  blight  (pattern-based CWE detection — fast, broad)
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

This pulls in `unblob` and `python-magic` from PyPI. `unblob` itself requires
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
         [--checks {extract,creds,binaries,all}]
         [--format {json,md}]
         [--blight-binary PATH]
         [--output FILE]
```

| Flag | Default | Description |
|---|---|---|
| `--firmware` | *(required)* | Path to the firmware image (raw blob, ZIP, tarball, vendor format). |
| `--workdir` | `./embalmer-work/` | Directory unblob extracts into. |
| `--checks` | `all` | Which checks to run: `extract`, `creds`, `binaries`, or `all`. |
| `--format` | `json` | Report format: `json` or `md`. |
| `--blight-binary` | `blight` | Path to the blight executable for the binary-analysis handoff. |
| `--output`, `-o` | *(stdout)* | Write the report to a file instead of stdout. |

### Checks

- **`extract`** — recursively extract the firmware via unblob and emit the
  extraction tree, file count, and extraction time.
- **`creds`** — walk the extracted filesystem for password hashes
  (`/etc/shadow`-style), hardcoded credentials in config files
  (`password=`, `api_key=`, `db_pass=`, …), and private keys (PEM blocks and
  well-known key filenames).
- **`binaries`** — locate ELF binaries in the extracted tree and hand each off
  to `blight`, aggregating blight's CWE findings into the report.
- **`all`** — run all three and produce a combined report.

`creds` and `binaries` both depend on extraction, so extraction always runs
when they are requested (its output appears in the report only if `extract` or
`all` was selected).

### Example workflow

Full audit of a router firmware image:

```sh
embalmer --firmware router.bin --checks all
```

JSON report to a file, extraction only:

```sh
embalmer --firmware router.bin --workdir ./work --checks extract -o report.json
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
  "checks": ["extract", "creds", "binaries"],
  "extraction": {
    "extraction_tree": { "...": "..." },
    "file_count": 1423,
    "extraction_time_ms": 8120,
    "extract_root": "./embalmer-work/"
  },
  "credentials": [
    { "category": "credential", "path": "...", "type": "password_hash", "severity": "high", "detail": "..." }
  ],
  "binaries": [
    { "category": "binary", "path": "...", "type": "CWE-120", "severity": "high", "detail": "..." }
  ]
}
```

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

The unblob and blight boundaries are mocked in the unit/smoke tests, so the
core suite runs in any environment. The `@pytest.mark.integration` tests
exercise real unblob extraction of the bundled fixture and a real subprocess
blight handoff.

---

## Scope (v0.1)

embalmer v0.1 is intentionally narrow. It does **not** include:

- Vendor-specific firmware formats beyond what unblob covers natively
- autopsy integration (blight is the only binary-analysis handoff in v0.1)
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
