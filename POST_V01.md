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
>
> **Update (Phase 2, Rotation 29):** **CVSS v4.0 scoring** is now supported. The
> single CVSS extractor (`severity._extract_cvss`, the chokepoint used by both
> binary-finding scoring *and* the `--sbom-cve` cross-reference) read only
> `cvssMetricV31`/`cvssMetricV30`/`cvssMetricV2` blocks — NVD's `cvssMetricV40`
> records (CVSS v4.0, published Nov 2023 and increasingly attached to recently
> published IoT CVEs) were silently ignored, so a CVE NVD scored *only* under
> v4.0 fell through to `info`/un-scored. `_extract_cvss` now consults a
> `_CVSS_METRIC_KEYS` ladder that includes `cvssMetricV40` (newest first) and
> takes the worst-case base score across whichever versions a CVE carries —
> CVSS base scores share the common 0.0–10.0 scale across versions, so the
> existing max-across-blocks logic is version-agnostic. Because the change is
> confined to the one extractor, every downstream path (binary `severity_score`,
> `sbom.vulnerabilities`, VEX, the EPSS/KEV promotion, the triage ladder) picks
> up v4.0 automatically with no signature or schema change. See
> `severity._CVSS_METRIC_KEYS`/`_extract_cvss`, `tests/test_severity.py`
> (`TestExtractCvssV40`), and `tests/test_sbom_cve.py`
> (`TestCrossReference.test_cvss_v40_only_cve_is_scored`). NOT in scope and still
> open: per-finding CVE attribution into the SBOM's vulnerability list / VEX
> (depends on the ossuary cross-reference, Rank 8).

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
>
> **Update (Phase 2, Rotation 17):** the SBOM is now exportable in **SPDX 2.3**
> (ISO/IEC 5962) in addition to CycloneDX 1.6 — the second self-contained
> SBOM-export gap. A new `--sbom-format {cyclonedx,spdx,both}` flag (default
> `cyclonedx`) threads through `pipeline.run(sbom_format=…)` and
> `Report.sbom_format` into `Report.to_dict`, which now emits the CycloneDX
> document under the historical `sbom.bom` key (default path is byte-for-byte
> unchanged) and/or an SPDX document under a new `sbom.spdx` key. The SPDX
> document is built from the *same* `Component` inventory: each package becomes
> an SPDX `package` with a sanitized, index-disambiguated `SPDXID`, the purl as
> a `PACKAGE-MANAGER`/`purl` external ref, the CPE (for binary-detected
> components) as a `SECURITY`/`cpe23Type` external ref, and a `CONTAINS`
> relationship from a synthetic root `firmware` package; unassertable fields use
> the `NOASSERTION` sentinel. CycloneDX and SPDX are the two NTIA-recognized SBOM
> formats, so emitting both maximizes downstream reach (CycloneDX for
> Dependency-Track/grype/trivy, SPDX for the GitHub dependency graph / ORT /
> federal pipelines). See `Sbom.to_spdx`/`Sbom.render` and `Component.to_spdx`/
> `Component.spdx_id` in `embalmer/sbom.py`, the `--sbom-format` flag in
> `embalmer/cli.py`, and `tests/test_sbom_spdx.py`. NOT in scope and still open:
> NVD CVE cross-referencing into either BOM's vulnerability list (depends on
> Rank 1 / ossuary Rank 8) and VEX statements.
>
> **Update (Phase 2, Rotation 19):** **VEX (Vulnerability Exploitability
> eXchange) export is now shipped** — the SBOM's exploitability companion and the
> "VEX statements" gap noted across Ranks 1, 2, and 8. A new `--vex` flag threads
> through `pipeline.run(emit_vex=…)` and attaches a **CycloneDX 1.6 VEX**
> document (the native `vulnerabilities[]` array, each with an `analysis` block)
> under a new `vex` report key (`vex.bom` is the standalone document, mirroring
> `sbom.bom`). This is *self-contained* — no ossuary dependency: it reuses the
> Rank 1 severity pipeline's already-attached `severity_score` evidence
> (`cve_id` + CVSS + EPSS + KEV) on each binary finding, distilling it into one
> per-CVE assertion. The `analysis.state` mapping is deliberately conservative —
> `exploitable` only on confirmed KEV membership or EPSS ≥ 0.5 (the same
> "more-likely-than-not" threshold the severity promotion uses), otherwise
> `in_triage`; embalmer never asserts `not_affected`/`resolved` because it cannot
> prove a negative from firmware evidence. `analysis.detail` records the
> rationale (KEV vs. EPSS vs. triage) and EPSS/KEV ride along as first-class
> CycloneDX `properties` so the verdict is auditable and re-derivable. The VEX is
> built after the dedup post-process (so `affects` reflects deduped findings) and
> is off by default — every existing report path is byte-for-byte unchanged.
> Requires the `binaries` check and severity enrichment; with `--no-enrich` the
> VEX is a valid empty "nothing asserted" document. See `embalmer/vex.py`
> (`Vex`/`VexEntry`), the `--vex` flag in `embalmer/cli.py`, the `vex` wiring in
> `embalmer/pipeline.py`/`embalmer/models.py`/`embalmer/report.py`, and
> `tests/test_vex.py`. Still open: NVD CVE cross-referencing of
> *package-database* SBOM components (Rank 8 ossuary `[suite]` half — depends on
> ossuary's v0.1 API, not yet available); the VEX asserts on binary CWE→CVE
> findings, which is the self-contained evidence already in-pipeline.
>
> **Update (Phase 2, Rotation 22):** **NTIA SBOM minimum-elements compliance
> checking is now shipped** — the procurement-side companion to SBOM generation.
> A new `--sbom-ntia-check` flag threads through `pipeline.run(ntia_check=…)` and
> scores the (post-component-merge) SBOM inventory against the seven minimum
> elements from the NTIA's July 2021 *Minimum Elements For an SBOM* report (the
> EO-14028 baseline): Supplier Name, Component Name, Version, Other Unique
> Identifiers, Dependency Relationship, Author of SBOM Data, Timestamp. The
> verdict is attached under a new `sbom.ntia` report key (alongside `sbom.bom` /
> `sbom.spdx`) as a structured pass/fail conformance report — overall
> `compliant` boolean, `missing_elements`, and a per-element result with
> per-component satisfied/total counts and a human `detail`. The check is
> deliberately honest: the per-component elements (name/version/unique-id) pass
> by construction, the document-level elements (relationship/author/timestamp)
> are stamped on every generated BOM, and **Supplier Name fails** because
> embalmer inventories firmware and emits the `NOASSERTION` sentinel for the
> upstream supplier it cannot resolve — so a real-firmware BOM reports
> `compliant: false` on exactly that one element (6/7) rather than overclaiming.
> Scoring is all-or-nothing per element (one version-less component fails the
> Version element for the whole BOM). Self-contained: reads the in-memory `Sbom`,
> no dependency, no network. Off by default — every existing report path is
> byte-for-byte unchanged. See `embalmer/ntia.py` (`check`/`NtiaReport`/
> `ElementResult`), the `--sbom-ntia-check` flag in `embalmer/cli.py`, the wiring
> in `embalmer/pipeline.py`/`embalmer/models.py`/`embalmer/report.py`, and
> `tests/test_ntia.py`. Still open: NVD CVE cross-referencing of package-database
> SBOM components (Rank 8 ossuary `[suite]` half — depends on ossuary's v0.1 API,
> not yet available).
>
> **Update (Phase 2, Rotation 23):** **SPDX license-expression validation is now
> shipped** — closing the one correctness gap in the SBOM license fields. Before
> this rotation the firmware-declared license string (an apk `L:` field) flowed
> *verbatim* into SPDX `licenseDeclared` and CycloneDX `license.name`, but the
> SPDX/CycloneDX specs require those fields to be valid **SPDX license
> expressions** — and firmware databases routinely declare non-SPDX tokens (a
> bare `GPL`, distro-isms like `custom`, vendor free text), so the emitted
> documents could fail strict validators (SPDX online validator, ORT,
> ntia-conformance-checker). A new self-contained `embalmer/licenses.py` validates
> the declared string against a curated SPDX identifier/exception set with a real
> expression grammar (`AND`/`OR`/`WITH`, parens, `+` or-later shorthand,
> `LicenseRef`/`DocumentRef` atoms, the `NOASSERTION`/`NONE` sentinels;
> case-insensitive lookup, canonical-case output). `Component.to_spdx` now emits a
> valid declared expression verbatim-canonicalized and routes a non-SPDX string
> through a document-local `LicenseRef-<sanitized>` paired with a
> `hasExtractedLicensingInfos` record (the spec's escape hatch), deduped per
> document; `Component.to_cyclonedx` emits a single id via `license.id`, a
> compound expression via the `expression` form, and non-SPDX free text via
> `license.name`. No new flag, no dependency, no network call — purely makes the
> existing `sbom`/`--sbom-format` output spec-correct; the only behavior change is
> that valid SPDX ids now correctly use `license.id`/canonical case instead of
> raw `license.name`. See `embalmer/licenses.py` (`is_valid_expression`/
> `canonicalize_expression`/`license_ref_id`), the license methods in
> `embalmer/sbom.py` (`Component._cyclonedx_license`/`_spdx_license_declared`/
> `extracted_license` and the `hasExtractedLicensingInfos` collection in
> `Sbom.to_spdx`), and `tests/test_licenses.py` + the new license cases in
> `tests/test_sbom_spdx.py`. Still open: NVD CVE cross-referencing of
> package-database SBOM components (Rank 8 ossuary `[suite]` half — depends on
> ossuary's v0.1 API, not yet available).
>
> **Update (Phase 2, Rotation 24):** **SPDX relationship-graph structural
> validation is now shipped** — the structural companion to the NTIA *content*
> check (Rotation 22). embalmer *generates* an SPDX 2.3 document, but nothing
> verified that the emitted relationship graph was internally consistent; a
> document can carry every required field and still be a broken artifact a strict
> validator rejects (a relationship endpoint that names no declared element, two
> packages colliding on one `SPDXID`, a package declared but never wired into the
> graph, or a document that DESCRIBES no root). A new self-contained
> `embalmer/spdx_validate.py` builds the SPDX document from the
> (post-component-merge) inventory and validates six graph invariants from SPDX
> 2.3 (§6/§7/§11): the reserved `SPDXRef-DOCUMENT` identifier, `SPDXID`
> uniqueness, `SPDXID` well-formedness (`SPDXRef-[A-Za-z0-9.-]+`), every
> relationship endpoint resolving to a declared element, a `DESCRIBES`/inverse
> `DESCRIBED_BY` root edge, and reachability of every package from the document
> root (a BFS over the relationship graph treated as undirected). A new
> `--sbom-validate-spdx` flag threads through `pipeline.run(spdx_validate_check=…)`
> and attaches a structured pass/fail report under a new `sbom.spdx_validation`
> key (alongside `sbom.bom`/`sbom.spdx`/`sbom.ntia`) — overall `valid` boolean,
> `failed_checks`, and a per-check result whose `offenders` list pinpoints the
> broken element identifiers. Because embalmer builds the graph correctly, a real
> generated document passes all six checks: the validation is a *guarantee* on
> the generator's output and a gate a consumer's pipeline can fail closed on. It
> does **not** require `--sbom-format spdx` (it validates the SPDX rendering of
> the inventory regardless of the emitted BOM format). Self-contained: reads the
> in-memory `Sbom`, no dependency, no network. Off by default — every existing
> report path is byte-for-byte unchanged. See `embalmer/spdx_validate.py`
> (`validate`/`validate_document`/`SpdxValidationReport`/`CheckResult`), the
> `--sbom-validate-spdx` flag in `embalmer/cli.py`, the wiring in
> `embalmer/pipeline.py`/`embalmer/models.py`/`embalmer/report.py`, and
> `tests/test_spdx_validate.py`. Still open: NVD CVE cross-referencing of
> package-database SBOM components (Rank 8 ossuary `[suite]` half — depends on
> ossuary's v0.1 API, not yet available).
>
> **Update (Phase 2, Rotation 25):** **NTIA Supplier-field enrichment is now
> shipped** — closing the highest-value half of the one NTIA element embalmer
> previously failed by construction. Before this rotation the `Component`
> dataclass had no `supplier` field at all, so every SBOM emitted `NOASSERTION`
> for the supplier (CycloneDX omitted it, SPDX hardcoded `"supplier":
> "NOASSERTION"`) and the NTIA check (Rotation 22) reported *Supplier Name* as
> unmet for the whole BOM. But the `components` check already knows the upstream
> **CPE vendor** for every binary-detected component (`busybox`, `openssl`,
> `haxx`, `gnu`, …) — that vendor *is* the upstream supplier, the one party
> embalmer can honestly assert. This rotation threads it through: the
> `components` check records the vendor on the finding (`extra["vendor"]`),
> `Component` gains a `supplier` field, `Component.from_component_finding` sets
> it from the vendor, and the renderers emit it spec-correctly — CycloneDX 1.6's
> first-class `supplier` organizationalEntity and SPDX 2.3's
> `Organization:`-prefixed `supplier`. The NTIA check now credits a real
> `supplier` field (the previously duck-typed positive branch becomes a real
> attribute), so a BOM made of binary-detected components reports
> `compliant: true`. Package-database components deliberately stay unasserted: a
> package DB names a maintainer/packager, not the upstream supplier, so claiming
> otherwise would overclaim. Honest posture preserved — a real mixed BOM still
> reports the Supplier gap (all-or-nothing per element), but the supplier data
> embalmer *can* assert now flows all the way into the documents and the
> conformance verdict instead of being silently dropped. No new flag, no
> dependency, no network call; the only behavior change is binary-detected
> components now carry an asserted supplier. See `embalmer/components.py` (the
> `vendor` finding field), `embalmer/sbom.py` (`Component.supplier`,
> `from_component_finding`, `to_cyclonedx`, `_spdx_supplier`/`to_spdx`,
> `to_dict`), and the new cases in `tests/test_components.py`,
> `tests/test_sbom_components.py`, and `tests/test_ntia.py`. Still open: NVD CVE
> cross-referencing of package-database SBOM components (Rank 8 ossuary `[suite]`
> half — depends on ossuary's v0.1 API, not yet available).
>
> **Update (Phase 2, Rotation 26):** **CycloneDX component purl validation is now
> shipped** — the CycloneDX-side companion to the SPDX relationship-graph
> validation (Rotation 24). embalmer *generates* a CycloneDX 1.6 BOM, and the
> single most important field on each `component` is its **purl** (Package URL):
> it is the identifier downstream vuln scanners (Dependency-Track, Grype,
> OSV-Scanner, OWASP dep-scan) **join on** to match a component against a CVE
> database. A component whose purl is malformed is silently un-matchable — the
> BOM looks complete, but every scanner that ingests it drops that component on
> the floor — yet nothing verified that the emitted purls conformed to the
> [package-url spec](https://github.com/package-url/purl-spec). A new
> self-contained `embalmer/purl_validate.py` builds the CycloneDX document from
> the (post-component-merge) inventory and validates six invariants the spec
> makes mandatory: the literal `pkg:` scheme, a non-empty lowercase spec-valid
> type drawn from the set embalmer emits (`deb`/`opkg`/`apk`/`generic`), a
> present name, a present version (the spec makes version optional, but a
> versionless SBOM component is useless for vuln matching, so embalmer requires
> it), canonically percent-encoded segments (so the purl round-trips), and
> well-formed `?key=value` qualifiers (lowercase key, present value, no repeated
> key). A new `--sbom-validate-purl` flag threads through
> `pipeline.run(purl_validate_check=…)` and attaches a structured pass/fail
> report under a new `sbom.purl_validation` key (alongside
> `sbom.bom`/`sbom.spdx`/`sbom.ntia`/`sbom.spdx_validation`) — overall `valid`
> boolean, `failed_checks`, and a per-check result whose `offenders` list
> pinpoints the broken purls with the reason. Because embalmer constructs every
> purl with `urllib.parse.quote` and a fixed type map, a real generated BOM
> passes all six checks: the validation is a *guarantee* on the generator's
> output and a gate a consumer's pipeline can fail closed on. Self-contained:
> reads the in-memory `Sbom`, no dependency, no network. Off by default — every
> existing report path is byte-for-byte unchanged. **Verification before
> implementing:** confirmed the *other* R26 candidate — license-expression
> validation for non-SPDX packages — was already shipped in Rotation 22
> (`embalmer/licenses.py`: `is_valid_expression`/`canonicalize_expression`/
> `license_ref_id`, routing non-SPDX tokens through the `LicenseRef`/`license.name`
> escape hatch), so this rotation implements the purl-validation candidate, which
> was not present. See `embalmer/purl_validate.py` (`validate`/`validate_purls`/
> `validate_document`/`PurlValidationReport`/`CheckResult`), the
> `--sbom-validate-purl` flag in `embalmer/cli.py`, the wiring in
> `embalmer/pipeline.py`/`embalmer/models.py`/`embalmer/report.py`, and
> `tests/test_purl_validate.py`. Still open: NVD CVE cross-referencing of
> package-database SBOM components (Rank 8 ossuary `[suite]` half — depends on
> ossuary's v0.1 API, not yet available).
>
> **Update (Phase 2, Rotation 27):** **NVD CVE cross-referencing of the SBOM's
> CPE-bearing components is now shipped** — the SBOM's vulnerability-list half,
> and the longest-standing "still open" item across Ranks 1/2/8, delivered
> *self-contained with no ossuary dependency*. The blocker the prior notes cited
> was the Rank 8 framing that pinned CVE cross-referencing to ossuary's
> known-vulnerable-component database. But embalmer already ships a complete,
> cached, timeout-guarded **NVD API v2** client (`embalmer/severity.py`, used for
> binary-finding severity scoring), and the SBOM already carries the one
> coordinate NVD matches on — a **CPE 2.3** name on every binary-detected
> component (`cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*`, set by the
> `components` check and merged into the BOM). A new self-contained
> `embalmer/sbom_cve.py` queries NVD's `cpeName` endpoint for each CPE-bearing
> component and resolves it to its applicable CVEs (e.g. OpenSSL 1.0.1f →
> CVE-2014-0160), scoring each via the existing `SeverityScore` ladder (CVSS
> tier, CISA-KEV pin-to-critical) and emitting them as **CycloneDX 1.6
> `vulnerabilities[]`** objects (NVD `source`, CVSS `rating`, `embalmer:in-kev`
> property, an `affects` ref back to the component purl) under a new
> `sbom.vulnerabilities` report key, with a quick-look summary
> (`cve_count`/`components_checked`/`components_with_cves`). A new `--sbom-cve`
> flag threads through `pipeline.run(sbom_cve_check=…)`. **Verification before
> implementing:** the *other* R27 candidate — NTIA supplier enrichment for
> *package-database* components — was deliberately **declined**, not implemented:
> Rotation 25 left package-DB supplier unasserted on principle (a package DB names
> a maintainer/packager, not the upstream supplier), so asserting one would
> overclaim, contradicting the project's honest-posture stance; this rotation
> implements the CVE cross-reference candidate instead. **Honest posture
> preserved:** only CPE-bearing components are cross-referenced — package-database
> components (`dpkg`/`opkg`/`apk`) carry a purl but no CPE, and NVD matches on
> CPE not purl, so they are left un-cross-referenced rather than guessing a
> vendor/product pair. Off by default (it makes network calls), skipped with
> `--no-enrich` (air-gapped), and degrades gracefully to an empty vulnerability
> list on any network error — every existing report path is byte-for-byte
> unchanged. See `embalmer/sbom_cve.py` (`cross_reference`/`CveMatch`/
> `SbomCveReport`), the `--sbom-cve` flag in `embalmer/cli.py`, the wiring in
> `embalmer/pipeline.py`/`embalmer/models.py`/`embalmer/report.py`, and
> `tests/test_sbom_cve.py`. Still open: the broader **ossuary** integration
> (Rank 8 `[suite]` half) — matching across component coordinates beyond NVD's
> CPE index (and package-DB components NVD cannot name) — depends on ossuary's
> v0.1 API, not yet available.

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

## Rank 8 — ossuary integration: known-vulnerable component matching `[suite]` — ✅ IMPLEMENTED (self-contained via NVD + OSV.dev; ossuary integration still optional)

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
>
> **Update (Phase 2, Rotation 30):** **OSV.dev CVE cross-referencing of the
> SBOM's package-database components is now shipped** — closing the
> longest-standing open item across Ranks 1/2/8, the other half of the SBOM CVE
> cross-reference that Rotation 27 (`--sbom-cve`) left open. R27 took the
> CPE-bearing (binary-detected) half against NVD self-contained; this rotation
> takes the **package-database** half (`dpkg`/`opkg`/`apk`) self-contained too —
> via **OSV.dev**, the canonical *purl-keyed* public vulnerability database
> (run by Google; the upstream Dependabot, OSV-Scanner, and most modern SCA
> tools already join on). The blocker the prior R8 notes cited was the framing
> that pinned package-DB cross-referencing to ossuary's known-vulnerable-component
> database; but every package-DB SBOM component already carries the one
> coordinate OSV matches on — a fully-formed **purl** (`pkg:deb/bash@5.0-4?arch=amd64`,
> `pkg:apk/busybox@1.35.0-r0`, `pkg:opkg/dropbear@2019.78-1`). A new
> self-contained `embalmer/sbom_osv.py` POSTs each package-DB component's purl
> to OSV.dev's `/v1/query` endpoint, distills the returned `vulns[]` records
> into CVE matches (CVE id from the OSV `id`/`aliases`, CVSS from
> `database_specific.cvss.score` or the typed `severity[]` entries, summary
> from `summary`/`details`), and scores each via the *same* multi-factor
> `SeverityScore` ladder the NVD path uses (CVSS tier, CISA-KEV
> pin-to-critical, EPSS promotion at the same `--epss-threshold`). Matches are
> **merged into the same `SbomCveReport`** the NVD cross-reference produces, so
> the report's `sbom.vulnerabilities` section is a **single unified CVE list**
> regardless of which upstream named which component — deduplicated by
> `(CVE id, component purl)` and tagged with a `sources` tuple
> (`("NVD",)` / `("OSV",)` / `("NVD", "OSV")`) the `source` label surfaces. A
> new `--sbom-osv` flag threads through `pipeline.run(sbom_osv_check=…)`.
> **Verification before implementing:** confirmed both R30 task candidates —
> NVD enrichment caching (shipped in Phase 2 Rotation 1's severity scoring:
> `_CACHE_DIR` / `_CACHE_TTL_SECONDS = 86400` in `embalmer/severity.py`) and
> CVSS v4.0 severity label mapping (shipped Rotation 29:
> `_CVSS_METRIC_KEYS = ("cvssMetricV40", …)` in `_extract_cvss`) — were already
> in tree, so this rotation implements the highest-value next-tier improvement
> that closed the longest-standing open item. **Honest posture preserved:** OSV
> is queried only for `dpkg`/`opkg`/`apk` components (the ones NVD's CPE index
> cannot name); binary-detected (CPE-bearing) components remain the NVD path's
> territory. The two upstreams never double-cover the same component, and the
> merged report dedups should they ever surface the same CVE on the same purl.
> Off by default (it makes network calls), skipped with `--no-enrich`
> (air-gapped), and degrades gracefully to no added CVEs on any network error —
> every existing report path is byte-for-byte unchanged (the historical
> NVD-only `source` string is preserved verbatim when only `--sbom-cve` runs).
> The 24h `~/.cache/embalmer/` cache the severity pipeline uses also caches OSV
> responses keyed on the queried purl, so a CI loop or upgrade-diff workflow
> makes at most one OSV request per unique purl per day. See
> `embalmer/sbom_osv.py` (`cross_reference`/`_match_component`/`_extract_osv_cvss`/
> `_cve_ids`), the `sources` field on `SbomCveReport`, the `--sbom-osv` flag in
> `embalmer/cli.py`, the wiring in `embalmer/pipeline.py`, the markdown title
> branching in `embalmer/report.py`, and `tests/test_sbom_osv.py`. **R8 status:**
> the self-contained data path the ossuary integration was meant to provide is
> now covered by NVD (R27, CPE-bearing) + OSV.dev (R30, package-DB) without an
> ossuary dependency; an ossuary integration remains an *optional* future
> enhancement for component coordinates beyond both indices' coverage, not a
> blocker for SBOM CVE cross-referencing.

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

---

## Rank 11 — Severity gate for CI (`--fail-on`) — ✅ IMPLEMENTED

> **Status: shipped (Phase 2, Rotation 31).** The original R31 brief asked to
> assess `--sbom-diff` (SBOM delta comparison) or NTIA minimum-elements
> validation as the next improvement. **Verification before implementing**:
> both candidates were already in tree — `--baseline` (Rotation 6,
> `embalmer/diff.py`) covers the SBOM-delta comparison (it diffs `sbom` adds /
> removes / changes alongside finding adds/removes), and `--sbom-ntia-check`
> (Rotation 22, `embalmer/ntia.py`) is the NTIA minimum-elements validation.
> So this rotation implements the **highest-value unshipped self-contained
> improvement** instead: the **`--fail-on` severity gate**, the one piece
> embalmer needs to be useful as a *CI/CD gate* rather than a scanner whose
> output a human reads.
>
> A new `--fail-on {none,info,low,medium,high,critical}` flag (default `none`,
> gate disabled) walks every finding-bearing section of the report
> (`credentials`/`certificates`/`binaries`/`components`) **and** every CVE match
> under `sbom.vulnerabilities` (the multi-factor CVSS+EPSS+KEV-scored matches
> from `--sbom-cve`/`--sbom-osv` — the most actionable CI signal), and returns
> a new exit code **10** when any finding lands at or above the requested tier.
> The threshold is *inclusive* — `--fail-on high` fails on `high` and
> `critical`. The report itself is still emitted in full (the gate observes,
> it does not suppress), and a ladder-ordered one-line tally
> (`fail-on=high [TRIGGERED]: critical=1, high=3, medium=12, low=2, info=8`)
> is written to stderr so the CI log shows both the report and the verdict.
> Severities outside the canonical ladder are silently ignored (the gate scores
> only on the documented `info/low/medium/high/critical` tiers). Exit code 10
> is distinct from every existing CLI failure code (1 usage, 2 extraction,
> 3 binary analysis, 4 baseline, 5 fetch), so a CI script can branch on
> *failed-due-to-findings* vs. *failed-to-run*. Self-contained: no network
> call, no new dependency, no I/O beyond the stderr summary line; default
> `none` keeps every existing exit code byte-for-byte unchanged. See
> `embalmer/gate.py` (`evaluate`/`GateResult`/`GATE_EXIT_CODE`/`FAIL_ON_CHOICES`),
> the `--fail-on` flag in `embalmer/cli.py`, the new "Severity gate for CI"
> README section, and `tests/test_gate.py`.

**What it does:** Add `--fail-on TIER` to the CLI so embalmer can be used as a
CI/CD gate (the same way `trivy`, `grype`, `snyk`, and OWASP dep-check are
used). When the gate trips, exit with a distinct non-zero code (10) so a
build script can fail on findings without conflating the failure with
embalmer-itself-crashed.

**Rationale:** Every other capability — severity scoring (R1), SBOM (R2), CVE
cross-reference (R8/R27/R30), VEX (R19) — produces *data*. None of them give a
CI pipeline a verb. `--fail-on` is the one piece that lets a build script
*act* on the data without writing its own JSON parser. It's the smallest
change that converts embalmer from "a scanner whose output a human reads"
into "a scanner CI runs unattended". Self-contained, no new dependencies, no
network, and additive — every existing exit code unchanged.

**Effort:** small

**References:**
- `trivy --severity HIGH,CRITICAL --exit-code 1` — the prior-art CI gate pattern
- `grype --fail-on high` — same pattern in Anchore's scanner
- OWASP Dependency-Check `--failOnCVSS 7.0`
