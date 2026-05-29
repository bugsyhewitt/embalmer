# embalmer — Post-v0.1 Improvement Directions

This document ranks the highest-value improvements for embalmer beyond v0.1. It is the
reference for Phase 2 Workers choosing what to implement next.

**Effort scale:**
- `small` — 1–3 days of focused implementation
- `medium` — 1–2 weeks including tests and README update
- `large` — 2–4 weeks, may require architectural changes or external tool integration

**Suite-synergy** items depend on or extend other necromancer projects (marked `[suite]`).

Items are ordered by analyst-time-saved per unit of implementation effort (ROI).

---

## Rank 1 — Severity scoring: CVSS/EPSS/KEV multi-factor triage — ✅ IMPLEMENTED

> **Status: shipped across two rotations.** The CVSS + KEV base scoring shipped
> earlier (`embalmer/severity.py`): binary CWE findings are resolved to
> representative NVD CVEs, scored by worst-case CVSS base score, and pinned to
> `critical` on CISA KEV membership; the `binaries` check enriches findings
> in-pipeline (`pipeline._enrich_binary_findings`) unless `--no-enrich` is set,
> attaching a `severity_score` block and replacing the finding's `severity`.
> All network calls are timeout-guarded, 24h-cached under `~/.cache/embalmer/`,
> and degrade gracefully offline.
>
> **Update (Phase 2, Rotation 13):** the **EPSS factor is now wired into the
> triage label**, closing the last gap in the multi-factor design — previously
> EPSS was fetched and reported but never affected severity. `compute_label`
> now promotes the CVSS base tier by one rung when EPSS ≥ 0.5 (the
> "more-likely-than-not to be exploited" threshold): a CVSS-6.0 `medium` finding
> with EPSS 0.8 is reported `high`. KEV still pins to `critical` (and can't be
> promoted past it); an `info` finding with no scored CVE is not promoted on
> EPSS alone. The promotion is recorded on a new `SeverityScore.epss_promoted`
> flag (surfaced as `epss_promoted: true` in the finding's `severity_score`) so
> the bump is auditable. See `SeverityScore.compute_label`/`_promote`,
> `EPSS_PROMOTE_THRESHOLD`, and `tests/test_severity.py` (`TestEpssPromotion`).
> NOT in scope and still open: per-finding CVE attribution into the SBOM's
> vulnerability list / VEX (depends on the ossuary cross-reference, Rank 8), and
> a configurable EPSS threshold flag.
>
> **Update (Phase 2, Rotation 14):** the **configurable EPSS threshold** is now
> shipped, closing the last self-contained gap in the multi-factor design. The
> previously-hardcoded 0.5 promotion cut-off is now the *default* of a
> `--epss-threshold P` CLI flag threaded through `pipeline.run` →
> `_enrich_binary_findings` → `score_cwe`/`score_cve` →
> `SeverityScore.compute_label(..., epss_threshold=...)`. Lowering the threshold
> triages more aggressively (more findings promoted); a value above 1.0 is
> unreachable for a 0.0–1.0 probability and so cleanly disables EPSS promotion
> while leaving CVSS and KEV scoring intact; a negative value is rejected by the
> CLI (exit 1). `None`/omitting the flag preserves the 0.5 default, so every
> existing call path is byte-for-byte unchanged. See
> `SeverityScore.compute_label`, `score_cwe`/`score_cve`, the `--epss-threshold`
> flag in `embalmer/cli.py`, and the `TestConfigurableEpssThreshold` /
> `TestCliEpssThresholdFlag` cases in `tests/test_severity.py`. NOT in scope and
> still open: per-finding CVE attribution into the SBOM's vulnerability list /
> VEX (depends on the ossuary cross-reference, Rank 8).

**What it does:** Replace the current hardcoded `info/medium/high` severity labels with a
structured, multi-factor score. For binary findings, map CWE IDs to NVD CVE data, pull
CVSS base scores, and layer in EPSS (Exploit Prediction Scoring System) and CISA's Known
Exploited Vulnerabilities (KEV) catalog to produce a triage-ready severity per finding.

**Rationale:** Current severity is static and arbitrary — `"high"` for any shadow hash,
`"info"` for every binary CWE. Real analysts triage by exploitability, not category.
A 2025 paper (arXiv 2601.01308) demonstrated that CVSS + EPSS + KEV multi-factor scoring
dramatically reduces alert fatigue versus base-CVSS-only. Critical IoT CVEs in 2024–2025
(e.g., CVE-2024-41592, CVSS 10.0 DrayTek buffer overflow) would be ranked against lower
CVSS findings automatically if scoring were in place.

**Effort:** medium

**References:**
- arXiv:2601.01308 — "Automated SBOM-Driven Vulnerability Triage for IoT Firmware"
- NIST NVD API v2 — https://nvd.nist.gov/developers/vulnerabilities
- EPSS API — https://api.first.org/data/v1/epss
- CISA KEV catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CVE-2024-41592 (DrayTek, CVSS 10.0) as motivating example

---

## Rank 2 — SBOM generation (CycloneDX JSON) — ✅ IMPLEMENTED

> **Status: shipped (Phase 2, Rotation 5).** embalmer now exposes a `sbom`
> check (`--checks sbom`, also included in `all`). It walks the extracted
> filesystem's package-manager databases — dpkg (`…/var/lib/dpkg/status`),
> opkg (`…/var/lib/opkg/status`, the `usr/lib`/`etc` variants, and
> `…/var/lib/opkg/info/*.control`), and apk (`…/lib/apk/db/installed`) — and
> emits a **CycloneDX 1.6** JSON BOM under the report's `sbom.bom` key, plus a
> flat `sbom.components` summary. Databases are matched by path suffix anywhere
> under the extract root (so nested unblob root filesystems are found); each
> package becomes a CycloneDX `component` with a purl
> (`pkg:deb/…`, `pkg:opkg/…`, `pkg:apk/…`). Only installed packages are
> included; removed/config-only entries are skipped; duplicates are
> deduplicated. See `embalmer/sbom.py` and `tests/test_sbom.py`.
>
> **Update (Phase 2, Rotation 12):** the version-string component cross-link is
> now shipped. When the `components` check runs alongside `sbom` (e.g.
> `--checks all`), binary-detected third-party libraries are merged into the
> CycloneDX BOM as `library` components with a `pkg:generic/<name>@<version>`
> purl, the CPE 2.3 in CycloneDX's first-class `cpe` field, and an
> `embalmer:detected-from = binary-strings` property; they are deduped against
> the package-database components by `(name, version)`. See
> `Sbom.merge_component_findings` in `embalmer/sbom.py`, the pipeline wiring in
> `embalmer/pipeline.py`, and `tests/test_sbom_components.py`. NOT in scope and
> still open: NVD CVE cross-referencing into the SBOM's vulnerability list
> (depends on Rank 1 severity scoring / NVD integration) and VEX statements.

**What it does:** Walk the extracted filesystem's package manager databases
(`/var/lib/dpkg/status`, `/var/lib/opkg/info/*.control`, `/lib/apk/db/installed`,
`/etc/opkg/status`) and emit a CycloneDX 1.6 JSON SBOM alongside the audit report.
Cross-reference identified packages against the NVD to surface CVE matches directly in
the SBOM's vulnerability list.

**Rationale:** SBOM generation is the firmware analysis capability most requested by
enterprise buyers post-EO-14028 (U.S. federal mandate). EMBA v2.0 (Dec 2024) ships a
CycloneDX F15 module as a headline feature. FACT does the same. embalmer currently
produces no package inventory at all — adding SBOM output immediately closes the gap with
both competitors for the "give me an inventory" use case. CycloneDX is the right format:
ECMA-424 standard, IoT/hardware BOM support, native VEX support for vulnerability data.

**Effort:** medium

**References:**
- EMBA v2.0 release (Dec 2024) — https://github.com/e-m-b-a/emba/releases/tag/v2.0.0-A-brave-new-world
- CycloneDX specification — https://cyclonedx.org/
- EO14028 SBOM mandate context — https://www.cisa.gov/sbom
- EMBA SBOM chapter — https://github.com/e-m-b-a/emba/wiki/The-EMBA-book-%E2%80%90-Chapter-5:-SBOM-and-vulnerability-aggregation

---

## Rank 3 — autopsy integration for deep binary analysis `[suite]` — ✅ IMPLEMENTED

> **Status: shipped (Phase 2, Rotation 2).** embalmer now exposes
> `--analyzer {blight,autopsy,both}` (default `blight` for backwards
> compatibility). With `autopsy` or `both`, embalmer shells out to
> `autopsy --format json --binary <elf>` for each discovered ELF and normalizes
> autopsy's native JSON envelope (`{"findings": [{"cwe": <int>, ...}]}`) into the
> unified `Finding` model. Implementation reuses the existing
> `binary_pipeline.SubprocessAnalyzer` unchanged — autopsy's output shape is
> already consumable by the shared `_item_to_finding` normalizer, so the autopsy
> analyzer differs from blight only in its CLI flags. See
> `embalmer/binaries.py` (`_make_autopsy_analyzer`, `analyze(analyzer=...)`),
> the `--analyzer`/`--autopsy-binary` CLI flags, and `tests/test_autopsy.py`
> (subprocess fully mocked — angr is never imported). NOT in scope and still
> open: CWE-190 in autopsy v0.1, severity mapping (Rank 1), parallel dispatch
> (Rank 9).

**What it does:** Add a `--analyzer autopsy` flag (alongside the existing blight default).
When selected, embalmer invokes autopsy's CLI for each discovered ELF binary instead of
blight. Autopsy performs whole-program angr-backed analysis (CWE-119, -190, -416, -78),
produces taint traces, and emits structured JSON findings. Normalize autopsy's
`BinaryFinding` schema into embalmer's `Finding` model and merge into the report.

**Rationale:** blight (radare2-backed pattern matching) is fast and broad. autopsy (angr
symbolic execution) is slow and deep. Real audits need both: blight for the sweep,
autopsy for the binaries that look suspicious. Both tools are at v0.1 in the necromancer
suite, with well-defined JSON schemas. The binary-pipeline abstraction already exists in
embalmer; adding autopsy is wiring a second analyzer through the same
`SubprocessAnalyzer` interface. This is the highest-leverage cross-suite integration
available.

**Effort:** small (binary-pipeline abstraction makes this mostly plumbing)

**Suite dependency:** autopsy v0.1 (angr, ELF/x86_64, CWE-119/190/416/78)

**References:**
- autopsy README — https://github.com/bugsyhewitt/autopsy
- blight README — https://github.com/bugsyhewitt/blight
- binary-pipeline SubprocessAnalyzer interface (embalmer/binaries.py)

---

## Rank 4 — Certificate and TLS configuration scanning

**What it does:** Add a `certs` sub-check to the credential scanner that locates
X.509 certificate files (`.crt`, `.pem`, `.cer`), parses them with Python's
`cryptography` library, and flags: self-signed certificates, certificates with
`NotAfter` already expired, certificates using deprecated algorithms (MD5, SHA-1, RSA
< 2048 bits), and wildcard certificates in embedded firmware.

**Rationale:** Hardcoded/expired TLS certificates are a recurring source of IoT firmware
CVEs. CVE-2024-9991 (Philips lighting) and CVE-2025-2189 (Tinxy) both involve embedded
credential material extractable from firmware. The current credential scanner catches
private keys and password hashes but is silent on certificates. Certificate findings
require no new external tools — the `cryptography` package is pure Python and pip-
installable. This extends the existing `creds` check with zero new system dependencies.

**Effort:** small

**References:**
- CVE-2024-9991 (Philips, hardcoded WiFi creds in binary firmware)
- CVE-2025-2189 (Tinxy, plaintext credentials in firmware)
- Python `cryptography` library — https://cryptography.io/

---

## Rank 5 — Diff mode: compare two firmware versions

**What it does:** Add `embalmer diff --before FIRMWARE_A --after FIRMWARE_B` that runs
the full extract→creds→binaries pipeline on both images and emits a structured diff
report: new/removed/changed files, new/resolved credential findings, new/resolved binary
findings, SBOM component version changes (if SBOM check is enabled).

**Rationale:** Firmware diff is the primary workflow for patch validation and regression
auditing. "Did the vendor actually fix CVE-X in this release?" requires comparing before
and after. FACT (Fraunhofer FKIE) lists firmware comparison as a headline capability in
its name and docs. The core machinery (two Report objects) already exists; diff mode is
a new CLI subcommand that runs the pipeline twice and structures the delta. Extraction
non-determinism is the primary complexity: unblob's output paths may vary across runs
for the same content; a content-hash based comparison (rather than path-based) is needed.

**Effort:** medium

**References:**
- FACT (Firmware Analysis and **Comparison** Tool) — https://github.com/fkie-cad/FACT_core
- README Scope (v0.1) explicitly lists diff mode as post-v0.1

---

## Rank 6 — binwalk fallback extraction backend

**What it does:** When unblob extraction fails or produces zero files, automatically
retry extraction with binwalk (v3, Rust) as a fallback. Expose `--extractor {unblob,
binwalk,auto}` flag where `auto` (default) tries unblob first and falls back to binwalk
on failure. Normalize binwalk's output directory structure to match unblob's so
downstream checks run unchanged.

**Rationale:** unblob extracts more formats and runs faster than binwalk, which is why
it is embalmer's primary extractor. But unblob has stricter format detection — formats
it doesn't recognize are silently skipped. binwalk's heuristic signature scanning catches
things unblob misses (some proprietary formats, partially corrupted images). EMBA
integrated binwalk v3 (Rust rewrite) in December 2024 alongside unblob. The community
forks of binwalk2 are EOL at December 2025; the Rust v3 rewrite is the right target.
README Scope (v0.1) explicitly calls this out as planned for v0.2.

**Effort:** medium

**References:**
- binwalk v3 (Rust) — https://github.com/ReFirmLabs/binwalk
- EMBA v2.0 Dec 2024 release — binwalk v3 added as initial extractor
- README Scope (v0.1): "a binwalk fallback is planned for v0.2"
- binwalk2 community forks: EOL Dec 2025

---

## Rank 7 — Structured finding deduplication and grouping — ✅ IMPLEMENTED

> **Status: shipped (Phase 2, Rotation 6).** embalmer now runs a single
> post-processing pass (`embalmer/summary.py`, wired into `pipeline.run` after
> severity enrichment) that (1) **deduplicates** findings sharing a
> category/type/severity/identity signature — collapsing e.g. 50 symlinked
> `/etc/shadow` copies into one credential finding carrying `count` and a
> sorted `paths` list; (2) **groups** binary findings by binary under a new
> top-level `binary_groups` key; and (3) emits a top-level `summary` block with
> `total` and `by_severity`/`by_category` counts, rendered first in both JSON
> and markdown. The credential identity keys on the config `key` (or detail);
> binary identity keys on function/symbol/address; certificates on the reason.
> Singletons still get `count: 1` + `paths`. The summary counts distinct
> (post-dedup) findings and only appears when a finding-bearing check ran. See
> `tests/test_summary.py`. NOT in scope and still open: cross-partition
> content-hash dedup of *files* (only findings are deduped here), and a
> database-backed dedup layer (FACT-style) — embalmer's pass is in-memory.

**What it does:** After all checks run, apply a deduplication + grouping pass before
rendering the report. Deduplicate: if the same credential pattern (same key name, same
hash prefix) appears in 50 symlinked copies of the same file, emit one finding with a
`count` and `paths[]` field. Group: cluster binary findings by binary path so the report
shows per-binary summaries alongside the flat findings list. Add a `summary` section to
the report top-level with finding counts by severity and category.

**Rationale:** Real firmware images have thousands of symlinks and duplicate files across
squashfs partitions. The current report emits one finding per file — a firmware with
50 copies of `/etc/shadow` emits 50 identical credential findings. This overwhelms the
report without adding information. FACT solves this with a database-backed dedup layer;
embalmer can solve it with a post-processing pass in the pipeline. A `summary` block
(total findings, high/medium/info counts) is the first thing an analyst looks at.

**Effort:** small

**References:**
- OWASP FSTM stage 4 (filesystem analysis) — https://scriptingxss.gitbook.io/firmware-security-testing-methodology
- firmwalker — https://github.com/craigz28/firmwalker (avoids duplicate reporting)

---

## Rank 8 — ossuary integration: known-vulnerable component matching `[suite]` — ◑ PARTIAL (extraction half shipped)

> **Status: extraction half shipped (Phase 2, Rotation 11); ossuary
> cross-reference still open.** embalmer now exposes a `components` check
> (`--checks components`, also included in `all`) that walks the extracted tree,
> recovers each file's printable strings in-process (a dependency-free
> `strings(1)` equivalent — no external binary), and matches them against a
> high-signal catalogue of third-party component version banners: BusyBox,
> OpenSSL (letter versions like `1.0.1f` captured intact), curl/libcurl,
> Dropbear, uClibc/uClibc-ng, zlib, glibc, OpenSSH, Lua, and wpa_supplicant.
> Each distinct component/version becomes an `info` finding
> (`category="component"`) carrying `component`, `version`, and a **CPE 2.3**
> identifier (e.g. `cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*`). Findings
> flow through the existing dedup/summary/diff post-processing (dedup + diff key
> on the CPE, so a version bump between firmware releases reads as remove-old +
> add-new). See `embalmer/components.py`, the report `components` section, and
> `tests/test_components.py`. **NOT in scope and still open (the `[suite]`
> half):** the ossuary CVE cross-reference — taking `OpenSSL 1.0.1f` and
> resolving it to CVE-2014-0160 via ossuary's known-vulnerable-component
> database, and emitting the matched CVEs onto the findings. That depends on
> ossuary's v0.1 API surface (not yet available in this environment); the
> `components` findings are deliberately the self-contained data path the
> ossuary integration will later consume. The version-string detection feeding
> the SBOM's component list (the Rank 2 cross-link) is now **shipped** (Phase 2,
> Rotation 12): `--checks all` merges binary-detected components into the
> CycloneDX BOM — see Rank 2's status note and `Sbom.merge_component_findings`.
>
> **Update (Phase 2, Rotation 15):** the **component catalogue is now widened**
> from 10 to 19 signatures, the self-contained extraction-side gap noted above.
> Added the next tier of components that recur across IoT firmware, each
> anchored on its canonical version banner (never a bare version number, so the
> catalogue stays false-positive-free): **lighttpd** (`lighttpd/1.4.55`),
> **dnsmasq** (the DNSpooq cluster), **mosquitto** (MQTT broker), **libupnp /
> pupnp** (CVE-2020-12695 CallStranger), **expat**, **libpng**, **bash**
> (Shellshock), **libpcap**, and **tcpdump**. Each carries its CPE 2.3
> coordinate exactly as before, so the ossuary cross-reference (still open) will
> consume the wider inventory unchanged. See `_SIGNATURES` in
> `embalmer/components.py`, the README `components` entry, and the
> `test_wider_catalogue_*` cases in `tests/test_components.py`. Still open: the
> ossuary CVE cross-reference (the `[suite]` half — depends on ossuary's v0.1
> API, not yet available in this environment).
>
> **Update (Phase 2, Rotation 16):** the **component catalogue is widened again**
> from 19 to 28 signatures — the next self-contained tier of components that
> recur across IoT firmware. Added: **U-Boot** (the bootloader present on nearly
> every embedded Linux device, a recurring secure-boot CVE source), the **Linux
> kernel** (the `Linux version …` banner — the single most important version to
> inventory), **Mbed TLS** (the constrained-IoT TLS stack), **GnuTLS** (the
> OpenSSL alternative), **SQLite** (the ubiquitous embedded database), **PCRE /
> PCRE2** (the regex library), **ncurses**, **libssh2** (the client-side SSH
> library, distinct from Dropbear/OpenSSH and frequently statically linked), and
> **GNU Wget**. As before, every signature anchors on the component's canonical
> version banner (never a bare version number), so the catalogue stays
> false-positive-free, and each finding carries its CPE 2.3 coordinate exactly as
> before — the ossuary cross-reference (still open) consumes the wider inventory
> unchanged. See `_SIGNATURES` in `embalmer/components.py`, the README
> `components` entry, and the `test_wider_catalogue_*` / `test_tier3_*` cases in
> `tests/test_components.py`. Still open: the ossuary CVE cross-reference (the
> `[suite]` half — depends on ossuary's v0.1 API, not yet available in this
> environment).

**What it does:** After extraction, walk the firmware tree for known third-party component
signatures (BusyBox version strings, OpenSSL version strings, curl version strings, uClibc
version strings) and cross-reference against ossuary's known-vulnerable-component
database. Emit a `components` section in the report with matched versions and their
associated CVEs.

**Rationale:** CveBinarySheet (arXiv 2501.08840, 2025) catalogued 1,033 CVEs across 16
IoT third-party components (BusyBox, curl, OpenSSL, etc.) across 5 CPU architectures.
Version string extraction from binaries is cheap (strings + regex). ossuary in the
necromancer suite is specifically designed for known-vulnerable-component matching. This
creates the primary data-path integration between embalmer and ossuary, positioning
embalmer as the orchestration layer for suite-wide firmware intelligence.

**Effort:** medium (depends on ossuary v0.1 API surface)

**Suite dependency:** ossuary v0.1

**References:**
- arXiv:2501.08840 — "CveBinarySheet: A Comprehensive Pre-built Binaries Database for IoT Vulnerability Analysis"
- ossuary — https://github.com/bugsyhewitt/ossuary
- EMBA S09 module (binary version detection) as prior art

---

## Rank 9 — Parallel binary analysis — ✅ IMPLEMENTED

> **Status: shipped (Phase 2, Rotation 9).** `embalmer.binaries.analyze` now
> dispatches each binary's analyzer invocation concurrently via a thread pool
> sized by a new `jobs` parameter, exposed on the CLI as `--jobs`/`-j` (default
> `cpu_count // 2`, floored at 1; values `<1` clamp to 1). Per-binary results
> are re-assembled in `find_binaries` discovery order, so report content and
> finding order are byte-for-byte identical to a sequential run regardless of
> `--jobs`. A `--progress` flag (auto-enabled when `--output` writes to a file)
> streams `[i/N] analyzed <path>` lines to stderr. **[Worker decision:
> `ThreadPoolExecutor`, not `ProcessPoolExecutor`]** — the real per-binary work
> is each analyzer's *subprocess* (blight/autopsy CLIs); the GIL is released
> while the child runs, so threads achieve the same wall-clock parallelism, and
> unlike processes they impose no pickling constraint on the injected analyzer
> callables / test mocks. See `embalmer/binaries.py` (`analyze`, `default_jobs`),
> the CLI `--jobs`/`--progress` flags, and `tests/test_parallel.py`. NOT in
> scope and still open: progress as a live counter/bar (current output is one
> line per completed binary), and parallelizing extraction or the creds/sbom
> walks (those are not the bottleneck for large images).

**What it does:** When running the `binaries` check on a firmware image with many ELF
binaries, dispatch blight (and/or autopsy) invocations in parallel using
`concurrent.futures.ProcessPoolExecutor`. Add `--jobs N` flag (default: CPU count / 2).
Emit progress output to stderr when stdout is a report file.

**Rationale:** Large firmware images (router, NAS, IP camera) commonly contain 200–500
ELF binaries. blight invocations are independent — they share no state. Running them
serially when hardware can parallelize them is purely a throughput waste. EMBA runs
parallel analysis natively (its web UI shows per-binary status). This improvement has
zero impact on report content and 100% impact on wall-clock time for large firmware.

**Effort:** small

**References:**
- Python `concurrent.futures` — stdlib, no new dependencies
- EMBA EMBArk performance: 100+ images/day on 64-core systems

---

## Rank 10 — graverobber integration: live firmware acquisition `[suite]` — ✅ IMPLEMENTED

> **Status: shipped (Phase 2, Rotation 10).** embalmer now accepts
> `--fetch-url URL`, which downloads the firmware image via graverobber before
> running the normal extract→creds/certs/binaries/sbom pipeline ("point at a
> vendor URL, get an audit report"). graverobber is invoked as
> `graverobber fetch --url <URL> --output <PATH>` through a single mockable
> subprocess seam (`embalmer/fetch.py` `_run_graverobber`), mirroring the
> unblob/binwalk/blight/autopsy conventions — so the unit suite runs without
> graverobber installed and a `@pytest.mark.integration` test exercises the real
> subprocess path against a stub executable. By default the download lands at
> `<workdir>/firmware.bin`; passing `--firmware PATH` alongside `--fetch-url`
> names the destination. `--graverobber-binary` overrides the executable name.
> Exactly one of `--firmware`/`--fetch-url` is required; a fetch failure exits 5
> and runs no analysis (the downloaded file's existence is verified even when
> graverobber exits 0). See `embalmer/fetch.py`, the CLI flags in
> `embalmer/cli.py`, `tests/test_fetch.py`, and the `test_cli_fetch_*` cases in
> `tests/test_smoke.py`. NOT in scope and still open: passing graverobber
> auth/credential options through (callers configure graverobber directly), and
> caching/resuming partial downloads.

**What it does:** Add `embalmer fetch --source graverobber --target URL` that invokes
graverobber to download the firmware image before running the analysis pipeline.
graverobber handles vendor-specific download formats, authentication, and binary blob
extraction. embalmer receives a local path and proceeds normally.

**Rationale:** The current workflow requires the user to supply a pre-downloaded firmware
blob. graverobber in the necromancer suite automates vendor firmware retrieval. Wiring
them together creates a "point at a vendor URL, get an audit report" workflow — the
highest-level automation goal of the necromancer suite. README Scope (v0.1) explicitly
lists "live firmware download from vendor sites" as post-v0.1.

**Effort:** small (graverobber provides a CLI; embalmer wraps it)

**Suite dependency:** graverobber v0.1

**References:**
- graverobber — https://github.com/bugsyhewitt/graverobber
- README Scope (v0.1): "Live firmware download from vendor sites"
