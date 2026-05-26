"""Pipeline orchestration.

Ties the individual checks together into a single audit run. This is the heart
of embalmer's reason to exist: it does not implement extraction, credential
scanning logic, or binary analysis here — it sequences them and assembles the
combined report.
"""

from __future__ import annotations

from pathlib import Path

from typing import Any

from . import binaries, creds, extract
from .models import Report

VALID_CHECKS = ("extract", "creds", "binaries", "all")


def resolve_checks(checks: str) -> list[str]:
    """Expand the --checks selector into the ordered list of checks to run."""
    if checks == "all":
        return ["extract", "creds", "binaries"]
    if checks not in VALID_CHECKS:
        raise ValueError(f"unknown check: {checks!r}")
    return [checks]


def run(
    firmware: str | Path,
    workdir: str | Path,
    checks: str,
    blight_binary: str = "blight",
    _blight_analyzer: Any = None,
) -> Report:
    """Run the requested checks and return an assembled Report.

    Extraction is a prerequisite for `creds` and `binaries`, so it always runs
    when those are requested even if `extract` itself was not asked for in the
    output. The `checks` list recorded in the report reflects what the user
    requested, not the implicit extraction dependency.

    Args:
        _blight_analyzer: Optional BinaryAnalyzer callable to inject for
            testing. Bypasses the real blight subprocess invocation.
    """
    requested = resolve_checks(checks)
    report = Report(firmware=str(firmware), checks=requested)

    need_extraction = any(c in requested for c in ("extract", "creds", "binaries"))
    extraction_result = None
    if need_extraction:
        extraction_result = extract.extract(firmware, workdir)

    if "extract" in requested:
        report.extraction = extraction_result

    if "creds" in requested:
        assert extraction_result is not None
        report.credentials = creds.scan(extraction_result.extract_root)

    if "binaries" in requested:
        assert extraction_result is not None
        report.binaries = binaries.analyze(
            extraction_result.extract_root,
            blight_binary=blight_binary,
            _analyzer=_blight_analyzer,
        )

    return report
