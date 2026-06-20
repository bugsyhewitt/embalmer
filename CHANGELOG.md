# Changelog

All notable changes to embalmer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added (cumulative since v0.1.0)
- 38 PRs merged on `origin/main` between initial commit and the v1.0.0 cut (PRs #1–#38):
  severity scoring (CVSS v3.0/v3.1/v4.0, EPSS, KEV), CVE cross-reference (NVD, OSV.dev),
  VEX enrichment + VEX-override import, SBOM generation (CycloneDX 1.6, SPDX 2.3),
  SBOM validation (NTIA minimum-elements, SPDX relationship-graph, SPDX license-expression,
  CycloneDX purl), SBOM compliance gates (`--sbom-license-check`, `--component-blocklist`,
  `--sbom-supplier-check`, `--sbom-age-check`, `--sbom-osv`, `--sbom-cve`,
  `--cvss-min-score`, `--vex-override`, `--fail-on`, `--license-exception`), firmware fetch
  from URL (`--fetch-url`), component diff against baseline JSON (`--diff baseline.json`),
  X.509 cert / TLS config scanning, credential / default-password scanning,
  gate (`--fail-on {info,low,medium,high,critical}`) for CI exit-code policy.
- **Wheel ship-gate** (PR #38, `tests/test_wheel_ship_gate.py`): 7 `@pytest.mark.ship_gate`
  tests pin the v1.0 wheel-install contract (wheel builds cleanly, version matches
  pyproject.toml, wheel installs into fresh venv, version importable in fresh venv,
  public-API smoke, `python -m embalmer` works, CHANGELOG [1.0.0] entry present + ordered).
- **`python -m embalmer` entry point** (PR #38, `embalmer/__main__.py`).
- **`embalmer --version` reports `embalmer 1.0.0`**.

### Changed
- **`pyproject.toml [project] version`**: `0.1.0` → `1.0.0`.
- **`embalmer/__init__.py __version__`**: `0.1.0` → `1.0.0`.
- **`tests/test_wheel_ship_gate.py`**: 6 hardcoded `0.1.0` version-pin refs updated to
  `1.0.0` (wheel filename regex on line 31; pyproject-version assert on line 54;
  `__version__` import assert on line 80; `embalmer --version` output asserts on lines
  91 and 104; module docstring at lines 1+3).

### Notes
- 801 tests passing at v1.0.0 (800 baseline = 794 non-integration + 6 ship_gate, plus 1 new
  `test_changelog_has_v1_0_0_entry` ship_gate test).
- No new runtime dependencies since v0.1.0.
- No breaking CLI changes since v0.1.0 (new flags are additive only).
- This is the first v1.0 production-ready release of embalmer.

[1.0.0]: https://github.com/bugsyhewitt/embalmer/releases/tag/v1.0.0

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
