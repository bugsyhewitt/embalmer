"""Pipeline orchestration.

Ties the individual checks together into a single audit run. This is the heart
of embalmer's reason to exist: it does not implement extraction, credential
scanning logic, or binary analysis here — it sequences them and assembles the
combined report.
"""

from __future__ import annotations

from pathlib import Path

from typing import Any

from . import (
    binaries,
    certs,
    components,
    creds,
    extract,
    ntia,
    purl_validate,
    sbom,
    sbom_cve,
    spdx_validate,
)
from .models import Report
from .severity import score_cwe
from .summary import postprocess
from .vex import Vex

VALID_CHECKS = ("extract", "creds", "certs", "binaries", "sbom", "components", "all")


def resolve_checks(checks: str) -> list[str]:
    """Expand the --checks selector into the ordered list of checks to run."""
    if checks == "all":
        return ["extract", "creds", "certs", "binaries", "sbom", "components"]
    if checks not in VALID_CHECKS:
        raise ValueError(f"unknown check: {checks!r}")
    return [checks]


def _enrich_binary_findings(
    findings: list, timeout: int = 10, epss_threshold: float | None = None
) -> None:
    """Attach severity_score to binary findings that carry a CWE-N type in-place."""
    for finding in findings:
        if finding.category != "binary":
            continue
        cwe_str = finding.type  # e.g. "CWE-120"
        if not cwe_str or not cwe_str.upper().startswith("CWE-"):
            continue
        try:
            cwe_id = int(cwe_str.split("-", 1)[1])
        except (IndexError, ValueError):
            continue
        score = score_cwe(cwe_id, timeout=timeout, epss_threshold=epss_threshold)
        if score is not None:
            finding.severity = score.label
            finding.extra["severity_score"] = score.to_dict()


def run(
    firmware: str | Path,
    workdir: str | Path,
    checks: str,
    analyzer: str = "blight",
    blight_binary: str = "blight",
    autopsy_binary: str = "autopsy",
    extractor: str = "auto",
    enrich: bool = True,
    enrich_timeout: int = 10,
    epss_threshold: float | None = None,
    sbom_format: str = "cyclonedx",
    ntia_check: bool = False,
    spdx_validate_check: bool = False,
    purl_validate_check: bool = False,
    sbom_cve_check: bool = False,
    emit_vex: bool = False,
    jobs: int | None = None,
    progress: bool = False,
    _blight_analyzer: Any = None,
    _binary_analyzers: list[Any] | None = None,
) -> Report:
    """Run the requested checks and return an assembled Report.

    Extraction is a prerequisite for `creds` and `binaries`, so it always runs
    when those are requested even if `extract` itself was not asked for in the
    output. The `checks` list recorded in the report reflects what the user
    requested, not the implicit extraction dependency.

    Args:
        analyzer: Which binary analyzer(s) to run for the `binaries` check —
            one of ``"blight"`` (default), ``"autopsy"``, or ``"both"``.
        blight_binary: Path or name of the blight CLI.
        autopsy_binary: Path or name of the autopsy CLI.
        extractor: Which extraction backend to use — ``"unblob"``,
            ``"binwalk"``, or ``"auto"`` (default: unblob primary, binwalk
            fallback on failure or empty output).
        sbom_format: Which SBOM BOM document(s) to emit under the report's
            ``sbom`` key for the ``sbom`` check — ``"cyclonedx"`` (default,
            under the ``bom`` key for back-compat), ``"spdx"`` (under ``spdx``),
            or ``"both"``.
        ntia_check: When True, score the SBOM against the NTIA SBOM
            minimum-elements (July 2021) and attach the conformance report under
            the report's ``sbom.ntia`` key. Requires the ``sbom`` check (the
            inventory it scores); a no-op otherwise.
        spdx_validate_check: When True, validate the structural integrity of the
            generated SPDX 2.3 relationship graph and attach the validation
            report under the report's ``sbom.spdx_validation`` key. Requires the
            ``sbom`` check (the inventory the SPDX document is built from); a
            no-op otherwise.
        purl_validate_check: When True, validate every CycloneDX component's purl
            (Package URL) against the package-url specification and attach the
            validation report under the report's ``sbom.purl_validation`` key.
            The CycloneDX-side companion to ``spdx_validate_check``. Requires the
            ``sbom`` check (the inventory the BOM is built from); a no-op
            otherwise.
        sbom_cve_check: When True, cross-reference the SBOM's CPE-bearing
            components against the NVD (services.nvd.nist.gov) and attach the
            matched CVEs under the report's ``sbom.vulnerabilities`` key (a
            CycloneDX vulnerabilities[] array, with a quick-look summary).
            Self-contained — reuses the cached, timeout-guarded NVD client the
            severity pipeline uses; no ossuary dependency. Only binary-detected
            components carry a CPE, so package-database components are not
            cross-referenced (NVD matches on CPE, not purl). Requires the
            ``sbom`` check; makes network calls (a no-op air-gapped, degrading to
            an empty vulnerability list).
        emit_vex: When True, build a CycloneDX VEX (Vulnerability Exploitability
            eXchange) document from the enriched binary findings' CVE evidence
            and attach it under the report's ``vex`` key. Requires the
            ``binaries`` check (the source of CVE evidence) and severity
            enrichment (``enrich=True``); with neither, the VEX is empty.
        epss_threshold: EPSS promotion cut-off for binary-finding severity
            enrichment. ``None`` (default) uses
            :attr:`severity.SeverityScore.EPSS_PROMOTE_THRESHOLD` (0.5). A value
            above 1.0 disables EPSS-driven promotion.
        jobs: Number of binaries to analyze concurrently in the ``binaries``
            check. ``None`` (default) uses half the CPU count.
        progress: When True, the ``binaries`` check emits per-binary progress
            to stderr.
        _blight_analyzer: Optional single BinaryAnalyzer callable to inject for
            testing. Bypasses the real subprocess invocation.
        _binary_analyzers: Optional list of BinaryAnalyzer callables to inject
            for testing the ``analyzer="both"`` aggregation path. Takes
            precedence over ``_blight_analyzer``.
    """
    requested = resolve_checks(checks)
    report = Report(
        firmware=str(firmware), checks=requested, sbom_format=sbom_format
    )

    need_extraction = any(
        c in requested
        for c in ("extract", "creds", "certs", "binaries", "sbom", "components")
    )
    extraction_result = None
    if need_extraction:
        extraction_result = extract.extract(firmware, workdir, extractor=extractor)

    if "extract" in requested:
        report.extraction = extraction_result

    if "creds" in requested:
        assert extraction_result is not None
        report.credentials = creds.scan(extraction_result.extract_root)

    if "certs" in requested:
        assert extraction_result is not None
        report.certificates = certs.scan(extraction_result.extract_root)

    if "binaries" in requested:
        assert extraction_result is not None
        report.binaries = binaries.analyze(
            extraction_result.extract_root,
            analyzer=analyzer,
            blight_binary=blight_binary,
            autopsy_binary=autopsy_binary,
            jobs=jobs,
            progress=progress,
            _analyzer=_blight_analyzer,
            _analyzers=_binary_analyzers,
        )
        if enrich and report.binaries:
            _enrich_binary_findings(
                report.binaries,
                timeout=enrich_timeout,
                epss_threshold=epss_threshold,
            )

    if "sbom" in requested:
        assert extraction_result is not None
        report.sbom = sbom.scan(extraction_result.extract_root)

    if "components" in requested:
        assert extraction_result is not None
        report.components = components.scan(extraction_result.extract_root)

    # Cross-link: when both the SBOM and component checks ran, fold the
    # binary-detected components (statically-linked libs no package database
    # lists) into the SBOM so the BOM is the single complete inventory. Deduped
    # against package-database components by (name, version). (POST_V01 Rank 2 /
    # Rank 8 cross-link — self-contained, no ossuary dependency.)
    if report.sbom is not None and report.components:
        report.sbom.merge_component_findings(report.components)

    # NTIA minimum-elements conformance: score the (now complete, post-merge)
    # SBOM inventory against the NTIA July 2021 baseline data fields and attach
    # the verdict under `sbom.ntia`. Off by default and only meaningful when the
    # SBOM check ran — no inventory, nothing to score.
    if ntia_check and report.sbom is not None:
        report.ntia = ntia.check(report.sbom)

    # SPDX relationship-graph structural validation: build the SPDX document from
    # the (post-merge) inventory and verify its graph is internally consistent
    # (unique/well-formed SPDXIDs, no dangling relationship endpoints, a
    # described root, no orphaned packages). The structural companion to the
    # NTIA content check. Off by default and only meaningful when the SBOM check
    # ran — no inventory, no document to validate.
    if spdx_validate_check and report.sbom is not None:
        report.spdx_validation = spdx_validate.validate(
            report.sbom, str(firmware)
        )

    # CycloneDX component purl validation: render the (post-merge) inventory to a
    # CycloneDX BOM and verify every component's purl conforms to the
    # package-url spec (pkg: scheme, valid type, name + version present, segments
    # correctly percent-encoded, well-formed qualifiers) — the syntax downstream
    # vuln scanners join on. The CycloneDX-side companion to the SPDX
    # relationship-graph validation. Off by default and only meaningful when the
    # SBOM check ran — no inventory, no BOM to validate.
    if purl_validate_check and report.sbom is not None:
        report.purl_validation = purl_validate.validate(
            report.sbom, str(firmware)
        )

    # NVD CVE cross-reference: resolve the SBOM's CPE-bearing components (the
    # binary-detected libraries) to their applicable CVEs via the public NVD API
    # and attach them under `sbom.vulnerabilities` as a CycloneDX vulnerabilities[]
    # array. Self-contained — reuses the cached, timeout-guarded NVD client the
    # severity pipeline uses; no ossuary dependency. Off by default (it makes
    # network calls) and only meaningful when the SBOM check ran. Honors
    # `enrich`: with `--no-enrich` (air-gapped) it is skipped rather than
    # attempting the network, mirroring the binary-finding enrichment gate.
    if sbom_cve_check and enrich and report.sbom is not None:
        report.sbom_cve = sbom_cve.cross_reference(
            report.sbom, timeout=enrich_timeout
        )

    # Post-process: deduplicate findings, group binaries, and build the summary.
    # Runs after enrichment so dedup keys on final (scored) severities and the
    # summary reflects triage-ready labels.
    postprocess(report)

    # VEX export: distill the enriched binary findings' CVE evidence (CVSS, EPSS,
    # KEV) into a CycloneDX VEX document. Built after postprocess so it reflects
    # the deduplicated findings, and only when explicitly requested — it is the
    # exploitability companion to the SBOM, not part of the default report.
    if emit_vex:
        report.vex = Vex.from_findings(report.binaries)

    return report
