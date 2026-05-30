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
      │                ├──►  purl  (CycloneDX component purl validation — `--sbom-validate-purl`)
      │                ├──►  CVE   (NVD CVE cross-reference of CPE-bearing components — `--sbom-cve`)
      │                ├──►  OSV   (OSV.dev CVE cross-reference of package-DB components — `--sbom-osv`)
      │                ├──►  LIC   (license-policy compliance check — `--sbom-license-check`)
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
         [--sbom-validate-spdx] [--sbom-validate-purl] [--sbom-cve] [--sbom-osv]
         [--sbom-license-check] [--disallow-license SPDX_ID]
         [--license-exception NAME:SPDX_ID] [--vex]
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
| `--sbom-validate-purl` | *(off)* | Validate every **CycloneDX component purl** (Package URL) against the package-url specification and attach a pass/fail report under `sbom.purl_validation`. The CycloneDX-side companion to `--sbom-validate-spdx`. Requires the `sbom` check. See [CycloneDX purl validation](#cyclonedx-purl-validation-sbom-validate-purl). |
| `--sbom-cve` | *(off)* | **Cross-reference** the SBOM's CPE-bearing components against the **NVD** and attach the matched CVEs under `sbom.vulnerabilities` (a CycloneDX `vulnerabilities[]` array with a CVSS rating, an **EPSS** exploit-prediction probability, and a CISA-KEV flag per CVE). Surfaces the CVEs that touch the firmware's third-party libraries (e.g. `OpenSSL 1.0.1f → CVE-2014-0160`) directly in the BOM, triaged by the same multi-factor CVSS+EPSS+KEV verdict the binary findings use. Self-contained — no ossuary dependency. Requires the `sbom` check (and `components` to populate CPE-bearing components); makes network calls and is skipped with `--no-enrich`. See [NVD CVE cross-reference](#nvd-cve-cross-reference-sbom-cve). |
| `--sbom-osv` | *(off)* | **Cross-reference** the SBOM's **package-database** components (`dpkg`/`opkg`/`apk`) against **OSV.dev** (api.osv.dev — Google's purl-keyed public vulnerability database, the upstream Dependabot and OSV-Scanner use) and merge the matched CVEs into the **same** `sbom.vulnerabilities` array `--sbom-cve` populates. The companion to `--sbom-cve`: NVD matches on CPE so it cross-references only binary-detected components, OSV matches on purl so it cross-references only package-DB components — pass both for full SBOM coverage. Self-contained — no ossuary dependency. Requires the `sbom` check; makes network calls and is skipped with `--no-enrich`. See [OSV.dev CVE cross-reference](#osvdev-cve-cross-reference-sbom-osv). |
| `--sbom-license-check` | *(off)* | **Categorize** every SBOM component's declared license (permissive / weak-copyleft / strong-copyleft / network-copyleft / public-domain / other / unknown / noassertion) and attach a compliance report under `sbom.licenses`. Pair with `--disallow-license SPDX_ID` (repeatable) to fail compliance when a specific SPDX id appears in the inventory. The license-policy companion to `--sbom-cve` / `--sbom-osv`: those surface the SBOM's *vulnerability* posture, this surfaces its *license* posture. Self-contained — no network call, no new dependency. Requires the `sbom` check. See [License-policy compliance check](#license-policy-compliance-check-sbom-license-check). |
| `--disallow-license` | *(none)* | SPDX identifier `--sbom-license-check` fails compliance on (e.g. `--disallow-license AGPL-3.0-only --disallow-license GPL-3.0-only`). Repeatable; case-insensitive. Has no effect without `--sbom-license-check`. |
| `--license-exception` | *(none)* | Per-component waiver against the `--disallow-license` policy in `NAME:SPDX_ID` form (e.g. `--license-exception mongodb:AGPL-3.0-only`). Repeatable. Clears the matched (component, license) pair from the gate but still records it under `exempted` for audit — the license-policy companion to a Trivy `.trivyignore` / OSV-Scanner ignore-file: a legal-cleared component does not fail the build while the policy still fails everywhere else. Component name matches case-insensitively; SPDX id is canonicalized. Has no effect without `--sbom-license-check`. |
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
| `--fail-on` | `none` | **CI severity gate** — exit with code **10** when any finding (credentials, certificates, binaries, components, or `sbom.vulnerabilities` CVE matches) lands at or above this tier (`info`, `low`, `medium`, `high`, `critical`). Threshold is **inclusive** — `high` fails on `high` and `critical`. Default `none` disables the gate. The report itself is still emitted in full; a one-line tally is written to **stderr**. See [Severity gate for CI (`--fail-on`)](#severity-gate-for-ci-fail-on). |
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

  The CPE is the coordinate a vulnerability database keys on. The `components`
  check itself performs **no CVE lookup** — it surfaces the component inventory
  with zero external dependencies, and the *presence* of a component is not
  itself a vulnerability, which is why severity is `info`. Resolving those CPEs
  to CVEs against the public NVD is now available self-contained via
  [`--sbom-cve`](#nvd-cve-cross-reference-sbom-cve) (e.g. `OpenSSL 1.0.1f →
  CVE-2014-0160`); a broader **ossuary** known-vulnerable-component integration
  (POST_V01 Rank 8) — matching across more component coordinates than NVD's CPE
  index covers — remains a separate, future change that will consume exactly
  these `component` findings.

  **SBOM cross-link.** When both `sbom` and `components` run (e.g. `--checks
  all`), each binary-detected component is also **merged into the CycloneDX
  SBOM** as a `library` component with a `pkg:generic/<name>@<version>` purl, its
  CPE 2.3 in the BOM's first-class `cpe` field, its upstream supplier (the CPE
  vendor — the project that ships the library) in the first-class `supplier`
  field, and an `embalmer:detected-from = binary-strings` property recording its
  provenance. The supplier is the one NTIA *Supplier Name* element embalmer can
  honestly assert (see [NTIA check](#ntia-minimum-elements-check-sbom-ntia-check));
  package-database components leave it unasserted because a package DB records a
  maintainer, not the upstream supplier.
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
  else `low`. No CVSS data → `info`. All four CVSS versions NVD emits are read —
  **CVSS v4.0** (the current standard, published Nov 2023), v3.1, v3.0, and
  legacy v2 — and the worst-case base score across whichever versions a CVE
  carries is used. CVEs scored *only* under v4.0 (increasingly common for
  recently-published IoT CVEs) are no longer silently dropped to `info`.
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

### Severity gate for CI (`--fail-on`)

A vulnerability scanner is only as useful in CI as its ability to **fail the
build** when something serious shows up. `--fail-on TIER` turns embalmer's
five-tier severity label (`info` / `low` / `medium` / `high` / `critical`) into
an exit-code policy:

```bash
# Fail the build if any high-or-critical finding is present.
embalmer --firmware fw.bin --checks all --sbom-cve --fail-on high
echo "exit=$?"   # 0 if clean, 10 if the gate triggered
```

What the gate observes:

- Every entry in the report's finding-bearing sections (`credentials`,
  `certificates`, `binaries`, `components`).
- Every CVE match under `sbom.vulnerabilities` (populated by `--sbom-cve` and/or
  `--sbom-osv`). A known-exploited CVE on a shipped library is the prototypical
  "fail the build" event, so SBOM CVE matches participate in the gate alongside
  the finding sections — they carry the same five-tier label, scored by the
  same CVSS+EPSS+KEV verdict the binary findings use.

Semantics:

- **Threshold is inclusive.** `--fail-on high` fails on `high` **and**
  `critical`. `--fail-on info` fails on any finding.
- **Default is `none`.** When `--fail-on` is not passed (or passed as `none`),
  the gate is disabled and every existing exit code is **byte-for-byte
  unchanged** — `--fail-on` is purely additive.
- **The report is still emitted in full.** The gate observes, it does not
  suppress. Whatever `--format` you chose (JSON, markdown, CSV, SARIF) still
  writes to stdout (or to `--output`); the gate only affects the **exit code**.
- **A one-line tally goes to stderr** so the CI log shows what tripped the
  gate:

  ```
  embalmer: fail-on=high [TRIGGERED]: critical=1, high=3, medium=12, low=2, info=8
  ```

  The tally is ladder-ordered (`critical → info`) regardless of which tiers
  the report carries; zero buckets are omitted. The `[ok]` variant is logged
  even on a clean run so a "fail-on=critical [ok]" line is part of the
  audit trail. Severities outside the documented ladder are silently ignored
  (the gate scores only on the canonical tiers, so its semantics stay
  predictable).
- **Exit code 10** is reserved for "gate triggered". The existing exit codes
  (0 success, 1 usage, 2 extraction, 3 binary analysis, 4 baseline, 5 fetch)
  are unchanged — so a CI script can tell *failed-due-to-findings* apart from
  *failed-to-run*:

  ```bash
  if ! embalmer --firmware fw.bin --sbom-cve --fail-on high; then
      case $? in
          10) echo "vulnerable findings present — failing build" ;;
          *)  echo "embalmer itself failed to run" ;;
      esac
      exit 1
  fi
  ```

Self-contained: no network call, no new dependency, no I/O beyond the stderr
summary line. The gate is a pure observation over the in-memory report.

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
        "db_path": "squashfs-root/var/lib/dpkg/status", "cpe": null, "supplier": null
      },
      {
        "name": "openssl", "version": "1.0.1f", "source": "binary",
        "architecture": null, "purl": "pkg:generic/openssl@1.0.1f",
        "db_path": "usr/lib/libcrypto.so",
        "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        "supplier": "openssl"
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
they carry a `cpe`, a `pkg:generic/…` purl, and a `supplier` (the upstream CPE
vendor). Package-database components have `"source"` of `dpkg`/`opkg`/`apk`, a
`null` `cpe`, and a `null` `supplier` (a package DB names a maintainer, not the
upstream supplier).

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
document reads "this firmware contains these packages". A binary-detected
component's upstream supplier (the CPE vendor) is emitted as a spec-valid
`Organization:`-prefixed `supplier`. Values embalmer cannot assert (download
origin, concluded license, and the supplier of a package-database component)
use SPDX's `NOASSERTION` sentinel, since embalmer inventories firmware rather
than resolving provenance.

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
| 1 | Supplier Name | **partial** | embalmer asserts the upstream supplier for **binary-detected components** (the CPE vendor — the project that ships the library, e.g. `openssl`, `haxx`, `gnu`); package-database components leave it unasserted (`NOASSERTION`), because a package DB names a *maintainer/packager*, not the upstream supplier. A BOM made only of binary-detected components meets this element; a BOM that mixes in package-DB components fails it (all-or-nothing). |
| 2 | Component Name | yes | every component carries a name |
| 3 | Version of the Component | yes | every component carries a version |
| 4 | Other Unique Identifiers | yes | every component carries a purl (and binary-detected components additionally a CPE) |
| 5 | Dependency Relationship | yes | the firmware→component relationship is stamped on every document |
| 6 | Author of SBOM Data | yes | the generating tool (embalmer / necromancer) is recorded as the SBOM author |
| 7 | Timestamp | yes | a UTC creation timestamp is stamped on every document |

The check is deliberately strict and **all-or-nothing per element**: a single
version-less component fails the Version element for the whole BOM, and a single
component with no asserted supplier fails the Supplier Name element. embalmer
asserts the supplier where it honestly can (the upstream vendor of a
binary-detected component) and emits `NOASSERTION` where it cannot (a package
database's maintainer is not the upstream supplier) — so a typical real-firmware
BOM that mixes package-DB and binary-detected components is reported as
`compliant: false` on exactly the Supplier Name element, the truthful federal
posture rather than an over-claim.

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

### CycloneDX purl validation (`--sbom-validate-purl`)

`--sbom-validate-purl` is the **CycloneDX-side** companion to
`--sbom-validate-spdx`: where that validates the SPDX relationship graph, this
validates that every CycloneDX `component.purl` (Package URL) conforms to the
[package-url specification](https://github.com/package-url/purl-spec). The purl
is the single most important field on a component — it is the identifier
downstream vulnerability scanners (Dependency-Track, Grype, OSV-Scanner, OWASP
dep-scan) **join on** to match a component against a CVE database. A component
whose purl is malformed is silently un-matchable: the BOM looks complete, but
every scanner that ingests it drops that component on the floor.

embalmer constructs every purl with a fixed type map and percent-encoding, so a
real generated BOM passes every check — the validation is a **guarantee** on the
generator's output, the same posture as the SPDX validator. It attaches a
pass/fail report under `sbom.purl_validation` and checks six invariants the
package-url spec makes mandatory:

| # | Check | What it verifies |
|---|---|---|
| 1 | purl scheme prefix | the purl begins with the literal `pkg:` scheme |
| 2 | purl type valid | a non-empty lowercase type made of the spec's allowed characters, drawn from the set embalmer emits (`deb`/`opkg`/`apk`/`generic`) |
| 3 | purl name present | a non-empty name component (a purl with no name identifies nothing) |
| 4 | purl version present | a non-empty version after `@` (an SBOM component with no version is useless for vuln matching) |
| 5 | purl segments correctly encoded | every component segment is canonically percent-encoded so the purl round-trips |
| 6 | purl qualifiers well-formed | each `?key=value` qualifier has a lowercase key, a present value, and no repeated key |

A failing check lists the offending purls (with the reason), so the report
pinpoints *which* component is broken, not just that something is.

`--sbom-validate-purl` requires the `sbom` check (it validates the CycloneDX BOM
built from that inventory) and is off by default — every existing report path is
byte-for-byte unchanged. It is self-contained: it builds and inspects the
CycloneDX document in memory, adds no dependency, and makes no network call.

```bash
embalmer --firmware router.bin --checks sbom --sbom-validate-purl -o report.json
# the validation report lives at .sbom.purl_validation in the JSON output
```

```jsonc
{
  "sbom": {
    "component_count": 12,
    "components": [ ... ],
    "bom": { ... },
    "purl_validation": {
      "standard": "package-url (purl) component validation",
      "valid": true,
      "component_count": 12,
      "checks_total": 6,
      "checks_passed": 6,
      "failed_checks": [],
      "checks": [
        { "check": "scheme_prefix", "label": "purl scheme prefix",
          "passed": true, "detail": "all 12 purl(s) begin with the 'pkg:' scheme" },
        { "check": "version_present", "label": "purl version present",
          "passed": true, "detail": "all 12 purl(s) carry a non-empty version" },
        { "check": "encoding_valid", "label": "purl segments correctly encoded",
          "passed": true, "detail": "all 12 purl(s) have correctly percent-encoded segments" }
      ]
    }
  }
}
```

In markdown (`--format md`) the same verdict renders as a **CycloneDX purl
validation** subsection of the SBOM section, with a per-check passed/failed
table. Pair it with `--sbom-validate-spdx` to validate both NTIA-recognized
formats in one run.

### NVD CVE cross-reference (`--sbom-cve`)

An SBOM inventories the components in a firmware image; `--sbom-cve` answers the
follow-on question every analyst asks next: **which of those components are
known to be vulnerable?** It cross-references the SBOM's components against the
public **NVD** (National Vulnerability Database) and attaches the matched CVEs
directly to the BOM under `sbom.vulnerabilities` — surfacing, for example, that a
firmware shipping `OpenSSL 1.0.1f` is exposed to **CVE-2014-0160 (Heartbleed)**
without running a single symbolic-execution pass.

This is self-contained — **no ossuary dependency**. It reuses the same cached,
timeout-guarded NVD API v2 client that severity scoring already uses, and the
one coordinate NVD matches on: a component's **CPE 2.3** name. The `components`
check recovers statically-linked third-party libraries (OpenSSL, BusyBox, curl,
…) from binaries' baked-in version strings and records a CPE for each; those
CPE-bearing components are merged into the SBOM, and `--sbom-cve` queries NVD's
`cpeName` endpoint for the CVEs applicable to each.

Only CPE-bearing components are cross-referenced. **Package-database components**
(`dpkg`/`opkg`/`apk`) carry a purl but no CPE — a Debian package name is not an
NVD vendor/product pair, and guessing one would produce false matches — so they
are left un-cross-referenced rather than overclaimed (the same honest posture the
[NTIA supplier field](#ntia-minimum-elements-check-sbom-ntia-check) takes).

Each matched CVE is triaged by the **same multi-factor verdict the binary
findings use** ([severity enrichment](#severity-enrichment-cvss--epss--kev)): a
CVSS base tier, CISA-KEV membership pinning to critical, and an **EPSS**
(exploit-prediction probability, FIRST.org) promotion — a moderate-CVSS CVE that
is *likely to be exploited* (EPSS ≥ `--epss-threshold`, default `0.5`) is bumped
one rung. The result is that a CVE reaches the **same severity label** whether it
surfaced from a CWE-detected binary finding or an SBOM CPE cross-reference; the
two paths no longer disagree.

Each matched CVE is emitted as a **CycloneDX 1.6 `vulnerabilities[]`** object — a
`source` (NVD), a CVSS `rating` (scored to the promoted info/low/medium/high/critical
label), an `embalmer:in-kev` property, an `embalmer:epss` property carrying the
exploit-prediction probability (and `embalmer:epss-promoted` when EPSS raised the
label, so the promotion is auditable), and an `affects` reference back to the
component's purl. A quick-look summary (`cve_count`, `components_checked`,
`components_with_cves`) rides alongside. EPSS is best-effort: a CVE with no EPSS
score (or an offline run) simply falls back to the CVSS/KEV-only label.

`--sbom-cve` requires the `sbom` check (and `components`, run by `all`, to supply
the CPE-bearing components). It is off by default and makes network calls; with
`--no-enrich` (air-gapped) it is skipped, and any network error degrades
gracefully to an empty vulnerability list — cross-referencing never crashes the
pipeline. Every existing report path is byte-for-byte unchanged.

```bash
embalmer --firmware router.bin --checks all --sbom-cve -o report.json
# the matched CVEs live at .sbom.vulnerabilities in the JSON output
```

```jsonc
{
  "sbom": {
    "component_count": 12,
    "components": [ ... ],
    "bom": { ... },
    "vulnerabilities": {
      "source": "NVD (services.nvd.nist.gov, CPE-name cross-reference)",
      "components_checked": 3,
      "components_with_cves": 1,
      "cve_count": 2,
      "vulnerabilities": [
        { "cve_id": "CVE-2014-0160", "purl": "pkg:generic/openssl@1.0.1f",
          "cvss": 7.5, "severity": "high", "in_kev": true, "epss": 0.97 }
      ],
      "bom": [
        { "id": "CVE-2014-0160",
          "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160" },
          "ratings": [ { "source": { "name": "NVD" }, "score": 7.5, "severity": "high", "method": "CVSSv31" } ],
          "properties": [ { "name": "embalmer:in-kev", "value": "true" }, { "name": "embalmer:epss", "value": "0.97" } ],
          "affects": [ { "ref": "pkg:generic/openssl@1.0.1f" } ] }
      ]
    }
  }
}
```

In markdown (`--format md`) the same data renders as an **NVD CVE
cross-reference** subsection of the SBOM section, with a per-CVE table
(CVE / component / CVSS / EPSS / severity / KEV); an EPSS-promoted label is
flagged inline (e.g. `high (EPSS)`) so the verdict is auditable from the report
alone.

### OSV.dev CVE cross-reference (`--sbom-osv`)

`--sbom-cve` answers "which of the firmware's **binary-detected** libraries are
known to be vulnerable?" by joining their **CPE** names against the NVD.
`--sbom-osv` is its companion for the **other half** of the SBOM — the
**package-database components** (`dpkg` / `opkg` / `apk`) that the
`sbom` check inventories from `/var/lib/dpkg/status` and friends. Those
components carry a **purl** but no CPE: a Debian package name is not an NVD
vendor/product pair, so the NVD path deliberately skips them rather than
overclaiming. `--sbom-osv` resolves them via [OSV.dev](https://osv.dev/) —
Google's **purl-keyed** public vulnerability database, the upstream Dependabot
and OSV-Scanner already join on — and merges the matched CVEs into the **same**
`sbom.vulnerabilities` array.

```bash
# Full SBOM CVE coverage: NVD for the CPE-bearing half, OSV for the package-DB half
embalmer --firmware router.bin --checks all --sbom-cve --sbom-osv -o report.json
```

The two flags are complementary, not redundant, and stay honest about which
upstream named which component:

| Component class | Identified by | Cross-referenced by | Flag |
|---|---|---|---|
| Binary-detected (statically linked libraries, e.g. OpenSSL in libcrypto.so) | CPE 2.3 | NVD (services.nvd.nist.gov, CPE-name query) | `--sbom-cve` |
| Package-database (dpkg / opkg / apk) | purl | OSV.dev (api.osv.dev, purl query) | `--sbom-osv` |

Matches are merged into one unified `sbom.vulnerabilities` section, deduplicated
by `(CVE id, component purl)` so a CVE that happens to surface from both
upstreams on the same purl appears once. The `source` field of that section
names the upstream(s) that contributed — `"NVD …"` for `--sbom-cve` alone (the
historical default, byte-for-byte unchanged), `"OSV.dev …"` for `--sbom-osv`
alone, or `"NVD … + OSV.dev …"` for both. Each merged CVE is the same shape as
the NVD path produces (`source` per CVE, CVSS `rating`, `embalmer:in-kev` /
`embalmer:epss` properties, `affects` ref to the component's purl), so every
existing CycloneDX consumer ingests the OSV-sourced CVEs unchanged.

Severity scoring is identical to the NVD path: a CVSS base tier (taken from
OSV's `database_specific.cvss.score` or the typed `severity[]` entries), KEV
pin-to-critical via the same CISA catalog, and EPSS promotion at the same
`--epss-threshold`. So a CVE reaches the same triage label whether it was
matched via NVD/CPE or OSV/purl — the two paths never disagree on what's
exploitable. Per-component matches are sorted worst-CVSS-first and capped (25
per component) so a widely-vulnerable package surfaces its highest-severity
CVEs without flooding the BOM.

`--sbom-osv` requires the `sbom` check (the package-DB inventory it
cross-references) and is off by default — every existing report path is
byte-for-byte unchanged. It makes network calls (OSV's `/v1/query` POST
endpoint); with `--no-enrich` (air-gapped) it is skipped, and any network error
degrades gracefully to no added CVEs — cross-referencing never crashes the
pipeline. The 24-hour `~/.cache/embalmer/` cache that the severity pipeline
uses also caches OSV responses, so repeated runs over the same firmware (a CI
loop, an upgrade diff) make at most one OSV request per unique purl per day.

```jsonc
{
  "sbom": {
    "component_count": 13,
    "components": [
      { "name": "openssl", "version": "1.0.1f", "source": "binary",
        "purl": "pkg:generic/openssl@1.0.1f",
        "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*", "...": "..." },
      { "name": "bash", "version": "5.0-4", "source": "dpkg",
        "purl": "pkg:deb/bash@5.0-4?arch=amd64", "cpe": null, "...": "..." }
    ],
    "bom": { "...": "..." },
    "vulnerabilities": {
      "source": "NVD (services.nvd.nist.gov, CPE-name cross-reference) + OSV.dev (api.osv.dev, purl cross-reference)",
      "components_checked": 2,
      "components_with_cves": 2,
      "cve_count": 2,
      "vulnerabilities": [
        { "cve_id": "CVE-2014-0160", "purl": "pkg:generic/openssl@1.0.1f",
          "cvss": 7.5, "severity": "high", "in_kev": true },
        { "cve_id": "CVE-2014-6271", "purl": "pkg:deb/bash@5.0-4?arch=amd64",
          "cvss": 10.0, "severity": "critical", "in_kev": true }
      ]
    }
  }
}
```

In markdown (`--format md`) the same data renders under a **CVE cross-reference
(NVD + OSV.dev)** subsection of the SBOM section (the title reflects which
upstream(s) ran), with the same per-CVE table — so the unified verdict is
auditable from one report regardless of which upstream resolved which CVE.

### License-policy compliance check (`--sbom-license-check`)

The SBOM records every component's declared license (the dpkg `License:` field,
the apk `L:` field, …) and renders it spec-correctly into CycloneDX / SPDX. What
the SBOM does **not** do is *score* those licenses against a policy — and a
license inventory is only actionable as a compliance signal when paired with
one. `--sbom-license-check` is the policy-side companion to the existing license
inventory: it categorizes every component's declared license into the coarse
bucket a legal / procurement team triages by and attaches a structured
pass/fail verdict the CI severity gate and any downstream tooling can act on.

```bash
# Informational-only mode (every category counted, no gate)
embalmer --firmware fw.bin --checks all --sbom-license-check

# Fail compliance when AGPL appears anywhere in the inventory
embalmer --firmware fw.bin --checks all \
         --sbom-license-check \
         --disallow-license AGPL-3.0-only \
         --disallow-license AGPL-3.0-or-later

# Combine with the severity gate so CI exits 10 on a license violation
# (license violations classify as a `high` finding in the gate's view)
embalmer --firmware fw.bin --checks all \
         --sbom-license-check --disallow-license GPL-3.0-only \
         --fail-on high
```

Every component's declared license is classified into one of:

| Category | Examples | Why it matters |
|---|---|---|
| `permissive` | MIT, Apache-2.0, BSD-*, ISC, Zlib | Attribution-only — typically green-lit by any policy. |
| `weak-copyleft` | LGPL-*, MPL-2.0, EPL-2.0, CDDL-* | File-level copyleft; dynamic linking generally safe. |
| `strong-copyleft` | GPL-2.0-only, GPL-3.0-only | Statically-linked GPL code may require source disclosure. |
| `network-copyleft` | AGPL-3.0-only, AGPL-3.0-or-later | Triggers source-disclosure even for network-only use — the SaaS-incompatible class. |
| `public-domain` | CC0-1.0, SPDX `NONE` | Unrestricted use. |
| `other` | A recognized SPDX id outside the firmware bucket map | Surfaced for the consumer to review. |
| `unknown` | Non-SPDX or unparseable (`custom`, vendor blob, bare `GPL`) | The SPDX validator routed it through `LicenseRef`. |
| `noassertion` | Database carried no license value | Honest gap — the firmware declared nothing. |

Compound expressions (`MIT OR AGPL-3.0-only`) classify by the **strictest** atom
— a consumer picking the AGPL branch still carries the AGPL obligation, so the
inventory must surface the strictest option. A `--disallow-license` policy
matches any disallowed id appearing in the expression, so a dual-licensed
component is blocked if either branch is on the list.

The verdict lives under `sbom.licenses` in the JSON report:

```json
{
  "sbom": {
    "licenses": {
      "standard": "SPDX license-policy compliance",
      "compliant": false,
      "disallow": ["AGPL-3.0-only", "GPL-3.0-only"],
      "component_count": 47,
      "disallowed_component_count": 2,
      "category_counts": {
        "permissive": 31,
        "weak-copyleft": 8,
        "strong-copyleft": 5,
        "network-copyleft": 1,
        "public-domain": 0,
        "other": 0,
        "unknown": 1,
        "noassertion": 1
      },
      "components": [
        {
          "purl": "pkg:apk/ffmpeg@5.1.4-r0",
          "name": "ffmpeg",
          "version": "5.1.4-r0",
          "declared": "GPL-3.0-only",
          "category": "strong-copyleft",
          "ids": ["GPL-3.0-only"],
          "allowed": false,
          "disallowed": ["GPL-3.0-only"]
        }
      ]
    }
  }
}
```

In markdown (`--format md`) the same data renders under a **License-policy
compliance** subsection of the SBOM section, with a per-category counts table
and (when the gate trips) a per-component disallowed-components table pinpointing
exactly which components matched the policy.

The check is deliberately honest: a component declaring `NOASSERTION` (or no
license at all) is reported as such rather than silently treated as compliant
or non-compliant — the verdict says *what the firmware declared*, not what
embalmer wishes it had. If a consumer wants to fail closed on a missing
declaration too, they read the `category_counts.noassertion` field; the check
itself stays conservative.

Self-contained — no network call, no new dependency, reuses the SPDX
validator/canonicalizer (`embalmer/licenses.py`) the SBOM renderers already
use. Off by default; every existing report path is byte-for-byte unchanged.

#### Per-component disallow exceptions (`--license-exception`)

A blanket `--disallow-license AGPL-3.0-only` is sometimes too coarse: legal
clears a single component on a case-by-case basis (commonly because the
vendor offers a separate commercial license, or the component is used in a
way that does not trigger the copyleft obligation), and the build should
not keep failing on that specific component while still failing on every
other AGPL component that slips in. `--license-exception` is the
per-component waiver — the license-policy companion to a Trivy
`.trivyignore` / OSV-Scanner ignore-file:

```bash
# Disallow AGPL across the board, but exempt mongodb specifically (legal
# has the commercial license on file; the audit trail is in the report).
embalmer --firmware fw.bin --checks all \
         --sbom-license-check \
         --disallow-license AGPL-3.0-only \
         --license-exception mongodb:AGPL-3.0-only

# Repeat the flag to waive multiple (component, license) pairs.
embalmer --firmware fw.bin --checks all --sbom-license-check \
         --disallow-license GPL-3.0-only \
         --disallow-license AGPL-3.0-only \
         --license-exception mongodb:AGPL-3.0-only \
         --license-exception ffmpeg:GPL-3.0-only
```

Each rule is `NAME:SPDX_ID`. The component name matches the SBOM's `name`
field case-insensitively (so the user does not need to know whether the
upstream casing is `mongodb` or `MongoDB`); the SPDX id is canonicalized
the same way `--disallow-license` is (so `mongodb:agpl-3.0-only` matches
`AGPL-3.0-only` in the inventory). A malformed token (missing the `:`
separator, empty name, empty id) exits 1 with a usage error to stderr.

The waiver clears only the **matched** (component, license) pair: an
exception on `mongodb` does not affect any other component, and an
exception on `mongodb:AGPL-3.0-only` does not waive any *other* license
declared by mongodb. A waived id is recorded under the component's
`exempted` list so the audit trail is preserved:

```json
{
  "sbom": {
    "licenses": {
      "compliant": true,
      "disallow": ["AGPL-3.0-only"],
      "exceptions": ["mongodb:AGPL-3.0-only"],
      "disallowed_component_count": 0,
      "exempted_component_count": 1,
      "components": [
        {
          "name": "mongodb",
          "version": "6.0",
          "declared": "AGPL-3.0-only",
          "category": "network-copyleft",
          "ids": ["AGPL-3.0-only"],
          "allowed": true,
          "exempted": ["AGPL-3.0-only"]
        }
      ]
    }
  }
}
```

In markdown the verdict line annotates the count
(`1 component(s) exempted via --license-exception`), the in-effect rules
render inline (`Per-component exceptions in effect: mongodb:AGPL-3.0-only`),
and an **Exempted components** table pinpoints exactly which components
were cleared and on which id.

The `exceptions` and `exempted_component_count` keys are only emitted when
at least one `--license-exception` was passed — every existing report path
(no exception flag) is byte-for-byte unchanged.

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
