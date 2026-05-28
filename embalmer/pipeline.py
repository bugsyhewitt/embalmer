"""Pipeline orchestration.

Ties the individual checks together into a single audit run. This is the heart
of embalmer's reason to exist: it does not implement extraction, credential
scanning logic, or binary analysis here — it sequences them and assembles the
combined report.
"""

from __future__ import annotations

from pathlib import Path

from typing import Any

from . import binaries, certs, components, creds, extract, sbom
from .models import Report
from .severity import score_cwe
from .summary import postprocess

VALID_CHECKS = ("extract", "creds", "certs", "binaries", "sbom", "components", "all")


def resolve_checks(checks: str) -> list[str]:
    """Expand the --checks selector into the ordered list of checks to run."""
    if checks == "all":
        return ["extract", "creds", "certs", "binaries", "sbom", "components"]
    if checks not in VALID_CHECKS:
        raise ValueError(f"unknown check: {checks!r}")
    return [checks]


def _enrich_binary_findings(findings: list, timeout: int = 10) -> None:
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
        score = score_cwe(cwe_id, timeout=timeout)
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
    report = Report(firmware=str(firmware), checks=requested)

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
            _enrich_binary_findings(report.binaries, timeout=enrich_timeout)

    if "sbom" in requested:
        assert extraction_result is not None
        report.sbom = sbom.scan(extraction_result.extract_root)

    if "components" in requested:
        assert extraction_result is not None
        report.components = components.scan(extraction_result.extract_root)

    # Post-process: deduplicate findings, group binaries, and build the summary.
    # Runs after enrichment so dedup keys on final (scored) severities and the
    # summary reflects triage-ready labels.
    postprocess(report)

    return report
