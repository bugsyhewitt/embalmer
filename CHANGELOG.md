# Changelog

All notable changes to embalmer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-19

### Added
- Initial v0.1.0 release — the necromancer-suite firmware analysis pipeline.
- CLI (`embalmer.cli`): single-binary orchestrator over unblob + blight + SBOM/CVE/OSV/VEX.
- Pipeline (`embalmer.pipeline.run`): extract → inspect → analyze → SBOM → report.
- Extraction (`embalmer.extract`): wraps unblob for 30+ container/archive formats.
- Binary analysis handoff to `blight` (`--no-blight` to skip) + `autopsy` (`--no-autopsy`).
- SBOM (CycloneDX 1.6 JSON via `--sbom-format cyclonedx-json`; SPDX 2.3 via `--sbom-format spdx-json`).
- SBOM NTIA minimum-elements compliance check (`--sbom-ntia-check`).
- SBOM SPDX relationship-graph structural validation (`--sbom-validate-spdx`).
- SBOM SPDX license-expression validation (`--sbom-validate-spdx-license`).
- SBOM CycloneDX component purl validation (`--sbom-validate-purl`).
- SBOM CPE→NVD CVE cross-reference (`--sbom-cve`).
- SBOM package-DB→OSV.dev CVE cross-reference (`--sbom-osv`).
- SBOM CVE matches enriched with EPSS exploit-prediction scoring.
- SBOM CVE matches enriched with CVSS v4.0 / v3.1 / v3.0 / v2 base scores.
- SBOM OSV vulnerability-record freshness gate (`--sbom-age-check`).
- SBOM CVE match minimum CVSS base score filter (`--cvss-min-score`).
- SBOM supplier-metadata compliance check (`--sbom-supplier-check`).
- SBOM component blocklist enforcement (`--component-blocklist`).
- SBOM license-policy compliance check (`--sbom-license-check` + `--license-exception`).
- CycloneDX VEX export (`--format vex`).
- VEX override import (`--vex-override`) — suppress filtered CVEs from a vendor VEX.
- SARIF 2.1.0 findings export (`--format sarif`).
- CSV flat findings export (`--format csv`).
- Markdown structured findings export (default).
- JSON structured findings export (`--format json`).
- Severity scoring (CVSS + EPSS + KEV multi-factor triage; `--epss-threshold P` flag).
- Gate (`--fail-on {info,low,medium,high,critical}`) for CI exit-code policy.
- Credential / default-password scanning (`/etc/shadow` hash cracking against weak-password wordlist).
- X.509 certificate / TLS config scan.
- Component blocklist (CVE / license / supplier / version policy).
- Component diff against a baseline JSON (`--diff baseline.json`).
- Firmware fetch from URL (`--fetch-url`).
- License-policy compliance (`--sbom-license-check`).
- `python -m embalmer` entry point (via `embalmer/__main__.py`).
- `embalmer --version` reports `embalmer 0.1.0`.

### Notes
- 37 PRs merged on `origin/main` between the Initial commit and the v0.1.0 cut.
  See `git log --oneline` for the full chain (PRs #1–#37).
- The `binary-pipeline` dep is pinned to a git+https URL (PyPI fallback TBD).
- Angr is required transitively for the deep symbolic-execution path (autopsy handoff).
