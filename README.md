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
 package inventory  ──►  SBOM  (CycloneDX 1.6 / SPDX 2.3 JSON from dpkg/opkg/apk databases)
      │                ├──►  NTIA  (minimum-elements conformance check — `--sbom-ntia-check`)
      │                ├──►  SPDX  (relationship-graph structural validation — `--sbom-validate-spdx`)
      │                └──►  VEX   (CycloneDX exploitability assertions from CVSS/EPSS/KEV — `--vex`)
      ▼
  structured firmware audit report  (JSON / markdown / CSV / SARIF)
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
embalmer (--firmware FIRMWARE | --fetch-url URL) [--workdir DIR]
         [--graverobber-binary PATH]
         [--checks {extract,creds,certs,binaries,sbom,components,all}]
         [--sbom-format {cyclonedx,spdx,both}] [--sbom-ntia-check]
         [--sbom-validate-spdx] [--vex]
         [--analyzer {blight,autopsy,both}]
         [--format {json,md,csv,sarif}]
         [--blight-binary PATH] [--autopsy-binary PATH]
         [--baseline SCAN.json]
         [--jobs N] [--progress]
         [--output FILE]
```

| Flag | Default | Description |
|---|---|---|
| `--firmware` | *(required\*)* | Path to the firmware image (raw blob, ZIP, tarball, vendor format). Required unless `--fetch-url` is given, in which case it is the local path the download is written to. |
| `--fetch-url` | *(none)* | Download the firmware from this vendor URL via **graverobber** before analyzing it (see [Live firmware acquisition](#live-firmware-acquisition)). Supply this **instead of** `--firmware`. |
| `--graverobber-binary` | `graverobber` | Path to the graverobber executable used by `--fetch-url`. |
| `--workdir` | `./embalmer-work/` | Directory the extractor unpacks into. |
| `--extractor` | `auto` | Extraction backend: `unblob` (primary), `binwalk` (binwalk v3), or `auto` (unblob first, fall back to binwalk on failure or empty output). |
| `--checks` | `all` | Which checks to run: `extract`, `creds`, `certs`, `binaries`, `sbom`, `components`, or `all`. |
| `--sbom-format` | `cyclonedx` | SBOM document format(s) for the `sbom` check: `cyclonedx` (CycloneDX 1.6, under `sbom.bom`), `spdx` (SPDX 2.3, under `sbom.spdx`), or `both`. See [SBOM export formats](#sbom-export-formats-sbom-format). |
| `--sbom-ntia-check` | *(off)* | Score the SBOM against the **NTIA minimum elements** (July 2021) and attach a pass/fail conformance report under `sbom.ntia`. Requires the `sbom` check. See [NTIA minimum-elements check](#ntia-minimum-elements-check-sbom-ntia-check). |
| `--sbom-validate-spdx` | *(off)* | Validate the structural integrity of the generated **SPDX 2.3 relationship graph** and attach a pass/fail report under `sbom.spdx_validation`. Requires the `sbom` check. See [SPDX relationship-graph validation](#spdx-relationship-graph-validation-sbom-validate-spdx). |
| `--vex` | *(off)* | Also emit a **CycloneDX VEX** (Vulnerability Exploitability eXchange) document under the report's `vex` key — the exploitability companion to the SBOM. See [VEX export](#vex-export-vex). |
| `--analyzer` | `blight` | Binary analyzer for the `binaries` check: `blight`, `autopsy`, or `both`. |
| `--format` | `json` | Report format: `json`, `md`, `csv`, or `sarif`. `csv` emits a flat, one-row-per-finding table — see [CSV findings export](#csv-findings-export-format-csv). `sarif` emits a SARIF 2.1.0 document — see [SARIF findings export](#sarif-findings-export-format-sarif). |
| `--blight-binary` | `blight` | Path to the blight executable for the binary-analysis handoff. |
| `--autopsy-binary` | `autopsy` | Path to the autopsy executable (used when `--analyzer` is `autopsy` or `both`). |
| `--baseline` | *(none)* | Compare this run against a previous embalmer JSON report and emit the **delta** instead of the full report (see [Diff mode](#diff-mode-baseline)). |
| `--jobs`, `-j` | *(half the CPU count)* | Number of binaries to analyze **in parallel** during the `binaries` check (see [Parallel binary analysis](#parallel-binary-analysis-jobs)). Use `1` to force sequential analysis. |
| `--progress` | *(off)* | Emit per-binary analysis progress to **stderr**. Auto-enabled when `--output` writes the report to a file. |
| `--no-enrich` | *(off)* | Skip CVSS/EPSS/KEV severity enrichment entirely (offline/air-gapped use) — see [Severity enrichment](#severity-enrichment-cvss--epss--kev). |
| `--epss-threshold` | `0.5` | EPSS probability (`0.0`–`1.0`) at or above which a finding's CVSS-based severity is promoted one tier. Lower is more aggressive; a value `> 1.0` disables EPSS promotion. No effect with `--no-enrich`. |
| `--output`, `-o` | *(stdout)* | Write the report to a file instead of stdout. |

### Extraction backends

Extraction is delegated to an external tool. embalmer supports two backends,
selected with `--extractor`:

- **`unblob`** — the primary. unblob recognizes 30+ formats, runs fast, and is
  the default workhorse. Picked alone with `--extractor unblob`.
- **`binwalk`** — [binwalk v3](https://github.com/ReFirmLabs/binwalk) (the Rust
  rewrite from ReFirmLabs). binwalk's heuristic signature scanning catches some
  proprietary or partially corrupted images that unblob silently skips. Picked
  alone with `--extractor binwalk`.
- **`auto`** *(default)* — try unblob first; if unblob errors out **or** produces
  zero files (an unrecognized format), embalmer clears the workdir and retries
  with binwalk. The backend that actually produced the tree is reported in the
  `extraction.extractor_used` field (and in the `## Extraction` markdown
  section), so a fallback is always visible.

Both backends normalize to the identical extraction-tree shape, so every
downstream check (`creds`, `certs`, `binaries`, `sbom`) runs unchanged
regardless of which backend won. `binwalk` must be installed and on `PATH`
to be used as a backend or fallback (see
[System dependencies](#system-dependencies-for-unblob)); the
`auto` default degrades gracefully — if binwalk is absent, an `unblob`-only run
behaves exactly as before.

### Live firmware acquisition

Instead of supplying a pre-downloaded blob with `--firmware`, point embalmer at
a vendor URL with `--fetch-url` and it will download the image first via
[graverobber](https://github.com/bugsyhewitt/graverobber) — the necromancer
suite's firmware-acquisition tool — then run the normal
extract → creds/certs/binaries/sbom pipeline on the result:

```sh
# point at a vendor URL, get an audit report
embalmer --fetch-url https://vendor.example/downloads/router-fw.bin --checks all
```

graverobber owns the vendor-specific download formats, authentication, and blob
extraction; embalmer just receives a local path back and proceeds. By default
the download lands at `<workdir>/firmware.bin`; pass `--firmware PATH` alongside
`--fetch-url` to choose the destination explicitly:

```sh
embalmer --fetch-url https://vendor.example/fw.bin --firmware ./fw/router.bin
```

graverobber is invoked as `graverobber fetch --url <URL> --output <PATH>`; use
`--graverobber-binary` if it is not on your `PATH` under that name. If
graverobber is missing or the download fails, embalmer exits non-zero (`5`) with
the underlying error on stderr and runs no analysis. Exactly one of `--firmware`
or `--fetch-url` must be supplied.

### Checks

- **`extract`** — recursively extract the firmware via the selected backend
  (see [Extraction backends](#extraction-backends)) and emit the extraction
  tree, file count, extraction time, and the `extractor_used` backend that
  produced the tree.
- **`creds`** — walk the extracted filesystem for password hashes
  (`/etc/shadow`-style), hardcoded credentials in config files
  (`password=`, `api_key=`, `db_pass=`, …), and private keys (PEM blocks and
  well-known key filenames).

  Shadow password hashes are additionally **cracked against a built-in
  default/weak-password wordlist**. A hash that exists is reported as a **HIGH**
  `password_hash` finding; a hash that *matches a known default* (the universal
  factory defaults, the Mirai botnet credential dictionary, and common vendor
  service passwords) is escalated to a **CRITICAL** `default_password` finding
  that records the recovered plaintext, the account name, and the crypt scheme.
  A device that ships with `root:admin` is a credential an attacker already has
  — the single most-exploited class of IoT firmware weakness — so embalmer
  surfaces it as the top-priority triage item rather than a generic "a hash is
  present". Cracking is pure-Python (`$1$` md5crypt, `$5$`/`$6$` sha-crypt) and
  needs no external tool; the wordlist is small and high-signal (it is *not* a
  general brute-force dictionary), so strong passwords are correctly left as
  plain `password_hash` findings. Locked/disabled accounts (`*`, `!`) and the
  memory-hard schemes (bcrypt `$2*$`, yescrypt `$y$`) are skipped.
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
  CWE findings into the report. Each CWE finding is then **severity-enriched**
  (unless `--no-enrich` is set) — see
  [Severity enrichment](#severity-enrichment-cvss--epss--kev) below.
- **`sbom`** — walk the extracted filesystem's package-manager databases and
  emit a JSON Software Bill of Materials of every installed package. The default
  format is **CycloneDX 1.6** (ECMA-424); **SPDX 2.3** (ISO/IEC 5962) and
  **both** are also available via `--sbom-format` (see
  [SBOM export formats](#sbom-export-formats-sbom-format)). Three package-manager
  families are inventoried:
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

  Pass `--sbom-ntia-check` to additionally score the SBOM against the **NTIA
  minimum elements** (July 2021) and attach a pass/fail conformance report under
  `sbom.ntia` — see
  [NTIA minimum-elements check](#ntia-minimum-elements-check-sbom-ntia-check).

  When the **`components`** check also runs (e.g. with `--checks all`), the
  third-party libraries recovered from binaries' version strings are **folded
  into the same SBOM** — see the cross-link note below the `components` entry.
- **`components`** — walk the extracted tree and recover **third-party
  component versions** from the version strings baked into firmware binaries
  (the same banner each project prints for `--version`). A high-signal
  catalogue is matched in-process — no external `strings(1)` binary required:
  **BusyBox**, **OpenSSL** (`1.0.1f`-style letter versions captured intact, so
  Heartbleed-era builds are distinguishable from patched ones), **curl /
  libcurl**, **Dropbear**, **uClibc / uClibc-ng**, **zlib**, **glibc**,
  **OpenSSH**, **Lua**, **wpa_supplicant**, **lighttpd**, **dnsmasq**,
  **mosquitto**, **libupnp** (the CallStranger component), **expat**,
  **libpng**, **bash**, **libpcap**, **tcpdump**, **U-Boot**, the **Linux
  kernel**, **Mbed TLS**, **GnuTLS**, **SQLite**, **PCRE / PCRE2**, **ncurses**,
  **libssh2**, and **Wget**. Each signature anchors on
  a component-specific banner prefix, never a bare version number, so the
  catalogue stays false-positive-free as it widens. Each distinct
  component/version becomes an `info` finding (`category: "component"`) carrying
  the matched
  `component`, `version`, and a [CPE 2.3](https://nvd.nist.gov/products/cpe)
  identifier (e.g. `cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*`).

  The CPE is the coordinate a vulnerability database keys on; embalmer records
  it but performs **no CVE lookup** — resolving `OpenSSL 1.0.1f` to
  CVE-2014-0160 is the **ossuary** suite integration (POST_V01 Rank 8) and is a
  separate, future change. This check is the self-contained *extraction* half of
  that workflow: it surfaces the component inventory today with zero external
  dependencies, and the ossuary cross-reference will later consume exactly these
  `component` findings. The *presence* of a component is not itself a
  vulnerability, which is why severity is `info` — exploitability is decided by
  the CVE match, not the version string.

  **SBOM cross-link.** When both `sbom` and `components` run (e.g. `--checks
  all`), each binary-detected component is also **merged into the CycloneDX
  SBOM** as a `library` component with a `pkg:generic/<name>@<version>` purl, its
  CPE 2.3 in the BOM's first-class `cpe` field, and an
  `embalmer:detected-from = binary-strings` property recording its provenance.
  This makes the SBOM the single complete inventory: package-manager databases
  list dynamically-installed packages, while statically-linked libraries
  (an OpenSSL baked into a binary, for example) appear only in their host
  binary's strings and would otherwise be invisible to a package-DB walk.
  Components are **deduplicated by `(name, version)`** — if the package database
  and a binary banner report the same name+version, the authoritative
  package-DB record is kept and the binary one is dropped; a *different* version
  of the same library (a static `openssl 1.0.1f` alongside a packaged
  `openssl 3.0.11`) is preserved as a distinct component. Running `sbom` without
  `components` leaves the SBOM as the package-DB inventory only.
- **`all`** — run all six and produce a combined report.

`creds`, `certs`, `binaries`, `sbom`, and `components` all depend on
extraction, so extraction always runs when they are requested (its output
appears in the report only if `extract` or `all` was selected).

### Severity enrichment (CVSS + EPSS + KEV)

A raw `binaries` finding only tells you *which* weakness class (CWE) a binary
exhibits — `info` is the analyzer's default, because the *presence* of a CWE
pattern is not, by itself, a triage priority. embalmer enriches each CWE finding
into a triage-ready severity by combining three complementary public sources
(this runs automatically; pass `--no-enrich` to skip it for offline/air-gapped
use):

- **CVSS** (from the NVD API) sets the **base tier**. embalmer resolves the
  finding's CWE to representative CVEs, takes the worst-case CVSS base score,
  and maps it: `>= 9.0` → `critical`, `>= 7.0` → `high`, `>= 4.0` → `medium`,
  else `low`. No CVSS data → `info`.
- **EPSS** (Exploit Prediction Scoring System, from `api.first.org`) **promotes
  the base tier by one rung** when the exploitation probability is at or above
  the promotion threshold — **0.5 by default**, i.e. the CVE is *more likely
  than not* to be exploited in the wild. A CVSS-6.0 (`medium`) finding with EPSS
  0.8 is reported as `high`; a CVSS-7.5 (`high`) finding with EPSS 0.6 is
  reported as `critical`. This is the alert-fatigue reducer: a moderate-CVSS
  weakness that is *actually being exploited* outranks an identically-scored one
  that nobody is touching. The promotion is recorded on an `epss_promoted: true`
  flag in the finding's `severity_score` so the bump stays auditable, and an
  already-`critical` finding is never escalated further. A finding with no CVSS
  data is not promoted on EPSS alone (EPSS without a scored CVE is not
  actionable).

  The threshold is **tunable per run** with `--epss-threshold P` (a `0.0`–`1.0`
  probability). Lower it (e.g. `--epss-threshold 0.2`) to triage more
  aggressively for a high-assurance target — more findings get promoted; raise
  it (e.g. `0.9`) to promote only near-certain exploitation. Because EPSS is a
  `0.0`–`1.0` probability, a threshold **above 1.0** (e.g. `--epss-threshold 2`)
  is unreachable and cleanly disables EPSS promotion while leaving CVSS and KEV
  scoring intact. A negative value is rejected. The flag has no effect under
  `--no-enrich` (which skips scoring entirely).
- **CISA KEV** (Known Exploited Vulnerabilities catalog) pins a finding to
  `critical` outright — KEV membership means *confirmed* in-the-wild
  exploitation, which trumps both CVSS and EPSS.

The enriched label replaces the finding's `severity` and the full breakdown is
attached under the finding's `severity_score` (`cvss`, `epss`, `in_kev`,
`epss_promoted`, `cve_id`, `label`). All network calls are timeout-guarded and
cached for 24 h under `~/.cache/embalmer/` (override with `EMBALMER_CACHE_DIR`);
any fetch failure degrades gracefully to the lower-confidence label rather than
crashing the run.

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
(`creds`/`certs`/`binaries`/`components`) ran; an extract-only report has no
`summary`. Component findings deduplicate on their CPE, so the same component
version found in dozens of files collapses to one finding with a `count`.

### Diff mode (`--baseline`)

When you upgrade firmware, the question is never "what does this image contain?"
— it is "what *changed* versus the last release?". Did the vendor actually fix
the CVE they claimed to? Did the patch quietly introduce a new hardcoded
credential? Did a package get added, removed, or bumped?

`--baseline` answers that. Point it at the JSON report from a **previous** run
and embalmer runs the requested checks on the current image, then emits a
structured **delta** instead of the full report:

```bash
# Capture a baseline of the old firmware
embalmer --firmware router-v1.bin --checks all --format json -o baseline.json

# Upgrade, re-scan, and see only what changed
embalmer --firmware router-v2.bin --checks all --baseline baseline.json
```

The delta is reported under a top-level `diff` key:

- **`findings`** — for each of `credentials`, `certificates`, `binaries`, and
  `components`, the findings that were **added** (present now, absent before),
  **removed** (present before, gone now — i.e. *resolved*), **unchanged**, or
  **severity_changed**. Findings are matched across the two scans by a stable
  identity (category, type, path, and underlying-artifact discriminator) that is
  **independent of severity**, so a finding whose CVSS/EPSS/KEV-enriched severity
  drifted between scans shows up under `severity_changed` (with `from`/`to`)
  rather than as a misleading remove + add pair. A component is identified by
  its CPE (component + version), so a version bump between firmware releases
  reads as the old version **removed** and the new version **added** — the
  upgrade signal an auditor wants.
- **`sbom`** — package components that were **added**, **removed**, **changed**
  (same package, new version — the patch-validation signal operators care about
  most, reported with `from`/`to`), or **unchanged**. SBOM components are matched
  by `(source, name)`, so a version bump is one `changed` entry, not an add and a
  remove.

The baseline must be the JSON output of a prior `embalmer` run (it is validated
for a top-level `firmware` key). The two scans need not have run the same
`--checks`; a section present in only one scan yields pure adds or removes.
`--baseline` honours `--format json` and `--format md` — pass `--format md` for
a human-readable diff. `--format csv` is **not** supported with `--baseline`
(the diff is a structured add/remove/change delta, not a flat finding list); the
combination exits with code `1` and a clear message. A missing or malformed
baseline file exits with code `4`.

This is the lightweight, deterministic form of firmware comparison: it reuses a
saved scan rather than re-extracting both images, sidestepping unblob's
extraction non-determinism entirely.

### CSV findings export (`--format csv`)

`--format csv` renders the report as a flat, **one-row-per-finding** table — the
shape an analyst imports straight into a spreadsheet, a ticketing system, or a
triage tool. Every credential, certificate, binary, and component finding the
run surfaced becomes a row, in that section order:

```bash
embalmer --firmware router.bin --checks all --format csv -o findings.csv
```

The header is a fixed, stable column set (consumers key on the header row, so
columns are only ever appended, never reordered or removed):

```
category,severity,type,path,count,detail,component,version,cpe,subject_cn,issuer_cn,expiry,reason,user,password
```

The first six columns are common to every finding; the remainder are the
per-category `extra` fields that matter in triage — `component`/`version`/`cpe`
for `components`, `subject_cn`/`issuer_cn`/`expiry`/`reason` for `certificates`,
and `user`/`password` for cracked `default_password` credentials (the recovered
account name and plaintext). A finding that doesn't carry a given field leaves
that cell blank. Values containing commas, quotes, or newlines are quoted per RFC 4180, so
the output round-trips cleanly through any standard CSV reader. An empty report
is a valid header-only CSV.

CSV is the **findings** export: the **SBOM** (the CycloneDX/SPDX documents) and
the **extraction tree** are nested structures that do not flatten to one row per
finding, so they appear only in `--format json`. Use JSON when you need the SBOM
or the tree; use CSV when you want the findings in a spreadsheet.

### SARIF findings export (`--format sarif`)

`--format sarif` renders the same finding inventory as a **SARIF 2.1.0** document
(the OASIS [Static Analysis Results Interchange Format][sarif-spec]) — the format
**GitHub Code Scanning**, Azure DevOps, GitLab, and most SAST dashboards ingest
directly. It is the format that turns a firmware audit into a Code Scanning alert
on a pull request without a bespoke converter:

```bash
embalmer --firmware router.bin --checks all --format sarif -o embalmer.sarif
```

Then, in a GitHub Actions workflow:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: embalmer.sarif
```

The document is a single SARIF `run` whose `tool.driver` is embalmer:

- **Every credential, certificate, binary, and component finding becomes a
  `result`** (the same inventory the CSV export flattens). The finding's `path`
  (a path *inside* the extracted firmware tree) is the result's
  `artifactLocation.uri`.
- **Each distinct `(category, type)` pair becomes a reusable rule**
  (`reportingDescriptor`) with a stable id like `embalmer.binary.CWE-120` — so
  dashboards group and trend by rule. CWE-typed binary findings additionally
  carry a CWE `tag`, a `helpUri` into the MITRE CWE definition, and a
  relationship into a CWE external taxonomy (the chip GitHub renders).
- **Severity maps to the SARIF `level`** (`error` for critical/high, `warning`
  for medium, `note` for low/info) and to the numeric
  `properties."security-severity"` GitHub ranks alerts by — taken from the real
  CVSS base score on a finding's `severity_score` block when present (the
  enrichment pipeline), otherwise a band derived from the label.
- **CVE / EPSS / KEV evidence and the per-category extras ride along in each
  result's `properties`**, so the verdict stays auditable and re-derivable.

Like CSV, SARIF is the **findings** export — the SBOM/VEX documents and the
extraction tree appear only in `--format json` — and it is **not** supported with
`--baseline` (a diff is a delta, not a finding list). An empty report is a valid
SARIF document with zero results.

[sarif-spec]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

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

### Parallel binary analysis (`--jobs`)

A typical router, NAS, or IP-camera firmware image contains hundreds of ELF
binaries. Each `blight` (and/or `autopsy`) invocation is an **independent**
subprocess — they share no state — so embalmer analyzes them concurrently.

By default embalmer dispatches up to `cpu_count / 2` binaries at once (floored
at 1), leaving headroom for the analyzer subprocesses' own threads. Control the
worker count with `--jobs`/`-j`:

```sh
# let embalmer pick (default: half the CPU count)
embalmer --firmware router.bin --checks binaries

# pin to 8 parallel analyzers
embalmer --firmware router.bin --checks binaries --jobs 8

# force fully sequential analysis (e.g. for deterministic profiling)
embalmer --firmware router.bin --checks binaries --jobs 1
```

Parallelism affects **only wall-clock time** — the report content and finding
order are byte-for-byte identical to a sequential run regardless of `--jobs`,
because per-binary results are re-assembled in discovery order.

For long-running scans you can stream progress to stderr with `--progress`
(`[i/N] analyzed <path>`). When you write the report to a file with
`--output`, progress is auto-enabled so the terminal isn't silent:

```sh
embalmer --firmware router.bin --checks binaries --jobs 8 \
         --output audit.json   # progress streams to stderr, report to audit.json
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

Generate an SPDX 2.3 SBOM instead — or both formats at once:

```sh
embalmer --firmware router.bin --checks sbom --sbom-format spdx -o sbom-report.json
# the standalone SPDX document lives at .sbom.spdx in the JSON output

embalmer --firmware router.bin --checks sbom --sbom-format both -o sbom-report.json
# emits .sbom.bom (CycloneDX) AND .sbom.spdx (SPDX) side by side
```

Inventory the third-party component versions baked into the firmware binaries
(BusyBox, OpenSSL, curl, …) — the self-contained first half of
known-vulnerable-component matching:

```sh
embalmer --firmware router.bin --checks components --format md
# each finding carries the component, version, and a CPE 2.3 identifier
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
      "category": "credential", "path": "etc/shadow", "type": "default_password",
      "severity": "critical",
      "detail": "account 'root' uses default/weak password 'admin' (cracked sha512crypt hash $6$abcdefgh$...)",
      "user": "root", "password": "admin", "scheme": "sha512crypt",
      "count": 1, "paths": ["rootfs/etc/shadow"]
    },
    {
      "category": "credential", "path": "etc/shadow", "type": "password_hash",
      "severity": "high", "detail": "...", "user": "svc",
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
        "db_path": "squashfs-root/var/lib/dpkg/status", "cpe": null
      },
      {
        "name": "openssl", "version": "1.0.1f", "source": "binary",
        "architecture": null, "purl": "pkg:generic/openssl@1.0.1f",
        "db_path": "usr/lib/libcrypto.so",
        "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*"
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
Components with `"source": "binary"` were recovered from a binary's version
string and merged in by the `components` check (see the SBOM cross-link above);
they carry a `cpe` and a `pkg:generic/…` purl. Package-database components have
`"source"` of `dpkg`/`opkg`/`apk` and a `null` `cpe`.

### SBOM export formats (`--sbom-format`)

CycloneDX and SPDX are the two SBOM formats recognized by the NTIA's *Minimum
Elements for an SBOM* (the EO-14028 baseline). Most tooling consumes one or the
other but not necessarily both: Dependency-Track, grype, and trivy are CycloneDX-
native, while the GitHub dependency graph, ORT, and many enterprise/federal
ingestion pipelines expect SPDX. `--sbom-format` lets you emit either — or both —
from the same package inventory so the report drops straight into whatever
consumer you have:

| `--sbom-format` | Emits | JSON key(s) |
|---|---|---|
| `cyclonedx` *(default)* | CycloneDX 1.6 (ECMA-424) | `sbom.bom` |
| `spdx` | SPDX 2.3 (ISO/IEC 5962) | `sbom.spdx` |
| `both` | Both documents | `sbom.bom` **and** `sbom.spdx` |

The default is unchanged from earlier releases: omitting `--sbom-format` produces
exactly the CycloneDX-only `sbom.bom` document as before. `sbom.components` (the
flat convenience summary) is always present regardless of format.

The `sbom.spdx` object is a complete, standalone **SPDX 2.3** document. Every
detected package becomes an SPDX `package` with a `SPDXID`, `versionInfo`, the
purl carried as a `PACKAGE-MANAGER`/`purl` `externalRef` (and, for
binary-detected components, the CPE as a `SECURITY`/`cpe23Type` `externalRef`),
and a `CONTAINS` relationship from a synthetic root `firmware` package — so the
document reads "this firmware contains these packages". Values embalmer cannot
assert (download origin, concluded license) use SPDX's `NOASSERTION` sentinel,
since embalmer inventories firmware rather than resolving provenance.

```jsonc
{
  "sbom": {
    "component_count": 1,
    "components": [ ... ],
    "spdx": {
      "spdxVersion": "SPDX-2.3",
      "dataLicense": "CC0-1.0",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "embalmer-sbom-router.bin",
      "documentNamespace": "https://necromancer/embalmer/router.bin-2026-05-28T00:00:00Z",
      "creationInfo": { "created": "2026-05-28T00:00:00Z", "creators": [ "Tool: embalmer", "Organization: necromancer" ] },
      "packages": [
        { "SPDXID": "SPDXRef-Package-firmware", "name": "router.bin", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, ... },
        { "SPDXID": "SPDXRef-Package-0-busybox", "name": "busybox", "versionInfo": "1.35.0-4",
          "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:deb/busybox@1.35.0-4?arch=amd64" } ], ... }
      ],
      "relationships": [
        { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-firmware" },
        { "spdxElementId": "SPDXRef-Package-firmware", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Package-0-busybox" }
      ]
    }
  }
}
```

#### License-expression validation

The SPDX `licenseDeclared` field and the CycloneDX `license` field are not free
text — the spec requires them to be valid **SPDX license expressions** (a
recognized SPDX identifier like `MIT` or `GPL-2.0-only`, a `LicenseRef-`
reference, the `NOASSERTION`/`NONE` sentinels, or a compound expression built
from those with `AND`/`OR`/`WITH`). Firmware package databases don't honor this:
an apk `L:` field routinely carries a non-SPDX token — a bare `GPL`, a
distro-ism like `custom`, or vendor free text — and emitting that verbatim
produces a document strict validators (the SPDX online validator, ORT,
ntia-conformance-checker) reject.

embalmer validates every declared license before emitting it, so both SBOM
formats stay schema-valid no matter what the firmware declared:

- A **valid** declared expression is emitted verbatim, canonicalized to its
  spec case — a database that lowercases `mit` / `apache-2.0` produces the
  proper `MIT` / `Apache-2.0`. In CycloneDX a single id uses `license.id` and a
  compound expression uses the `expression` form (the only spec-legal places
  for each).
- A **non-SPDX** string is never smuggled into a standards field. In SPDX it
  becomes a document-local `LicenseRef-<sanitized>` in `licenseDeclared`, paired
  with a `hasExtractedLicensingInfos` entry that records the original verbatim
  text — exactly the escape hatch the SPDX spec provides for "a license that is
  not on the SPDX License List". In CycloneDX it uses `license.name` (the
  spec's free-text field) rather than `license.id`.

For example, an apk package declaring `L:custom` yields:

```jsonc
{
  "sbom": {
    "spdx": {
      "packages": [
        { "SPDXID": "SPDXRef-Package-0-vendorlib", "name": "vendorlib",
          "licenseDeclared": "LicenseRef-custom", ... }
      ],
      "hasExtractedLicensingInfos": [
        { "licenseId": "LicenseRef-custom", "extractedText": "custom", "name": "custom" }
      ]
    }
  }
}
```

while a package declaring `L:MIT` keeps `"licenseDeclared": "MIT"` and emits no
extracted-license entry. The result is an SBOM that is both honest about what
the firmware declared and valid against the SPDX/CycloneDX schemas.

### NTIA minimum-elements check (`--sbom-ntia-check`)

Producing an SBOM is only half the federal ask — the procurement question is
whether the SBOM actually meets the baseline. The NTIA's July 2021 report *The
Minimum Elements For a Software Bill of Materials (SBOM)* — the document
EO‑14028 points at — defines **seven minimum elements** every conformant SBOM
must carry. `--sbom-ntia-check` scores embalmer's SBOM against those elements
and attaches a structured pass/fail conformance report under `sbom.ntia`, so a
consumer can answer "does this BOM meet the NTIA minimum?" without re-deriving
the rules.

The seven minimum elements, and how an embalmer-generated BOM scores against
each:

| # | NTIA element | Met by embalmer? | Why |
|---|---|---|---|
| 1 | Supplier Name | **no** | embalmer inventories firmware and cannot resolve a package's upstream supplier — it emits the `NOASSERTION` sentinel, which NTIA counts as *not met*. This is the one honest gap. |
| 2 | Component Name | yes | every component carries a name |
| 3 | Version of the Component | yes | every component carries a version |
| 4 | Other Unique Identifiers | yes | every component carries a purl (and binary-detected components additionally a CPE) |
| 5 | Dependency Relationship | yes | the firmware→component relationship is stamped on every document |
| 6 | Author of SBOM Data | yes | the generating tool (embalmer / necromancer) is recorded as the SBOM author |
| 7 | Timestamp | yes | a UTC creation timestamp is stamped on every document |

The check is deliberately strict and **all-or-nothing per element**: a single
version-less component fails the Version element for the whole BOM. It honestly
reports the Supplier Name gap rather than over-claiming completeness — so a
typical real-firmware BOM is reported as `compliant: false` on exactly the
Supplier Name element (6/7), which is the truthful federal posture for a BOM
generated from a binary image.

`--sbom-ntia-check` requires the `sbom` check (it scores that inventory) and is
off by default — every existing report path is byte-for-byte unchanged. It is
self-contained: it reads the in-memory SBOM, adds no dependency, and makes no
network call.

```bash
embalmer --firmware router.bin --checks sbom --sbom-ntia-check -o report.json
# the conformance report lives at .sbom.ntia in the JSON output
```

```jsonc
{
  "sbom": {
    "component_count": 12,
    "components": [ ... ],
    "bom": { ... },
    "ntia": {
      "standard": "NTIA Minimum Elements (July 2021)",
      "compliant": false,
      "component_count": 12,
      "elements_total": 7,
      "elements_satisfied": 6,
      "missing_elements": [ "Supplier Name" ],
      "elements": [
        { "element": "supplier_name", "label": "Supplier Name", "satisfied": false,
          "components_satisfied": 0, "components_total": 12,
          "detail": "0/12 component(s) carry an asserted supplier; embalmer ... emits NOASSERTION ..." },
        { "element": "component_name", "label": "Component Name", "satisfied": true, ... },
        { "element": "timestamp", "label": "Timestamp", "satisfied": true, ... }
      ]
    }
  }
}
```

In markdown (`--format md`) the same verdict renders as an **NTIA
minimum-elements conformance** subsection of the SBOM section, with a per-element
met/not-met table.

### SPDX relationship-graph validation (`--sbom-validate-spdx`)

The NTIA check validates the SBOM's *content* (does it carry the minimum data
fields?); `--sbom-validate-spdx` is its **structural** companion — it validates
that the generated SPDX 2.3 document is an internally-consistent **relationship
graph**. An SPDX document can carry every required field and still be a broken
artifact: a relationship can point at an `SPDXID` no element declares, two
packages can collide on one `SPDXID`, a package can be declared but never wired
into the graph (orphaned, unreachable from the document root), or the document
can fail to DESCRIBE any root at all. Strict SPDX validators (the SPDX online
validator, ORT, `ntia-conformance-checker`) reject such documents, and a
downstream dependency graph silently drops the unreachable nodes.

embalmer builds the graph correctly today, so this validation is a **guarantee**
on the generator's output: it attaches a pass/fail report under
`sbom.spdx_validation` confirming the emitted SPDX document is well-formed, and
gives a consumer a structured verdict to gate a pipeline on. It checks six graph
invariants from SPDX 2.3 (§6, §7, §11):

| # | Check | What it verifies |
|---|---|---|
| 1 | Document identifier | the document declares the reserved `SPDXRef-DOCUMENT` as its own `SPDXID` |
| 2 | SPDXID uniqueness | every element's `SPDXID` is unique (a duplicate makes relationship endpoints ambiguous) |
| 3 | SPDXID well-formed | every `SPDXID` matches `SPDXRef-[A-Za-z0-9.-]+` |
| 4 | Relationship endpoints resolve | every `spdxElementId` / `relatedSpdxElement` names a declared element — no dangling edge |
| 5 | Document describes a root | at least one `DESCRIBES` (or inverse `DESCRIBED_BY`) edge connects `SPDXRef-DOCUMENT` to a root element |
| 6 | No orphaned packages | every declared package is reachable from `SPDXRef-DOCUMENT` by following relationship edges |

A failing check lists the offending element/relationship identifiers, so the
report pinpoints *which* element is broken, not just that something is.

`--sbom-validate-spdx` requires the `sbom` check (it validates the SPDX document
built from that inventory) and is off by default — every existing report path is
byte-for-byte unchanged. It is self-contained: it builds and inspects the SPDX
document in memory, adds no dependency, and makes no network call. (It does **not**
require `--sbom-format spdx`; it validates the SPDX rendering of the inventory
regardless of which BOM document the report emits.)

```bash
embalmer --firmware router.bin --checks sbom --sbom-validate-spdx -o report.json
# the validation report lives at .sbom.spdx_validation in the JSON output
```

```jsonc
{
  "sbom": {
    "component_count": 12,
    "components": [ ... ],
    "bom": { ... },
    "spdx_validation": {
      "standard": "SPDX 2.3 relationship-graph validation",
      "valid": true,
      "package_count": 13,
      "relationship_count": 13,
      "checks_total": 6,
      "checks_passed": 6,
      "failed_checks": [],
      "checks": [
        { "check": "document_identifier", "label": "Document identifier",
          "passed": true, "detail": "document declares the reserved SPDXRef-DOCUMENT identifier" },
        { "check": "relationship_endpoints", "label": "Relationship endpoints resolve",
          "passed": true, "detail": "all 13 relationship endpoint(s) resolve to declared elements" },
        { "check": "no_orphan_packages", "label": "No orphaned packages",
          "passed": true, "detail": "all 13 package(s) are reachable from SPDXRef-DOCUMENT" }
      ]
    }
  }
}
```

In markdown (`--format md`) the same verdict renders as an **SPDX
relationship-graph validation** subsection of the SBOM section, with a per-check
passed/failed table.

### VEX export (`--vex`)

An SBOM tells you *what is in* the firmware; a **VEX** (Vulnerability
Exploitability eXchange) document tells you *which of the vulnerabilities that
touch it are actually exploitable*. VEX is the SBOM's companion artifact under
the NTIA framing — it lets a consumer suppress the noise of vulnerabilities that
are present-but-not-exploitable and focus triage on the ones that matter.

`--vex` is free with the analysis embalmer already does. The
[severity-enrichment pipeline](#severity-enrichment-cvss--epss--kev) already
resolves each binary CWE finding to a representative NVD CVE and attaches three
exploitability signals — **CVSS** base score, **EPSS** probability, and **CISA
KEV** membership. `--vex` folds that evidence into a **CycloneDX 1.6** VEX
document (the native `vulnerabilities` array, each carrying an `analysis` block),
under the report's `vex` key. No extra network calls, no new dependency — it is a
pure transform over the enriched findings.

embalmer asserts the VEX `analysis.state` **conservatively**, only from evidence
it actually has:

| Evidence | Asserted state |
|---|---|
| CVE in CISA KEV (confirmed exploited in the wild) | `exploitable` |
| EPSS probability ≥ `0.5` (more likely than not to be exploited) | `exploitable` |
| CVE resolved but no exploitation evidence | `in_triage` |

embalmer never asserts `not_affected` or `resolved` — it cannot prove a negative
from firmware strings, so the honest default is "an analyst still needs to look
at this". The `analysis.detail` field records *why* each state was chosen
(KEV vs. EPSS vs. triage) so the assertion is auditable, and EPSS/KEV ride along
as first-class `properties` so a downstream tool can re-derive the verdict.

`--vex` requires the `binaries` check (the source of CVE evidence) and severity
enrichment. With `--no-enrich` there is no CVE evidence, so the VEX is an empty —
but valid — "nothing asserted" document.

```bash
embalmer --firmware router.bin --checks binaries --vex -o report.json
# the standalone CycloneDX VEX document lives at .vex.bom in the JSON output
```

The `vex` section carries a quick-look summary (`vulnerability_count`,
`exploitable_count`, and a per-CVE list) plus the full standalone document under
`vex.bom`:

```jsonc
{
  "vex": {
    "vulnerability_count": 2,
    "exploitable_count": 1,
    "vulnerabilities": [
      { "cve_id": "CVE-2014-0160", "state": "exploitable", "cvss": 7.5, "epss": 0.97, "in_kev": true, "severity": "critical", "affected_paths": [ "usr/bin/httpd" ] }
    ],
    "bom": {
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "metadata": { "component": { "type": "firmware", "name": "router.bin" }, ... },
      "vulnerabilities": [
        {
          "id": "CVE-2014-0160",
          "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160" },
          "analysis": { "state": "exploitable", "detail": "Listed in CISA KEV ..." },
          "ratings": [ { "source": { "name": "NVD" }, "score": 7.5, "severity": "critical", "method": "CVSSv31" } ],
          "properties": [ { "name": "embalmer:in-kev", "value": "true" }, { "name": "embalmer:epss", "value": "0.97" } ],
          "affects": [ { "ref": "usr/bin/httpd" } ]
        }
      ]
    }
  }
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

> **Optional: binwalk fallback.** To use `--extractor binwalk` or let the
> `auto` default fall back to binwalk, install
> [binwalk v3](https://github.com/ReFirmLabs/binwalk) (the Rust rewrite) and
> ensure `binwalk` is on `PATH`. binwalk is **not required** for an
> unblob-only run.

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

- Vendor-specific firmware formats beyond what the extractors cover natively
- A web dashboard
- Emulation (running extracted binaries under QEMU)

> **Post-v0.1 updates:**
> - a binwalk v3 fallback extraction backend has since shipped — see
>   [Extraction backends](#extraction-backends) and `--extractor`.
> - live firmware download from vendor sites has since shipped via graverobber —
>   see [Live firmware acquisition](#live-firmware-acquisition) and `--fetch-url`.
> - third-party component version detection (BusyBox, OpenSSL, curl, …) has since
>   shipped — see the `components` check above and `--checks components`. CVE
>   cross-reference of those versions (the ossuary integration) is still
>   post-v0.1.

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
