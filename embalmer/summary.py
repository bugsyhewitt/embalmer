"""Finding deduplication, grouping, and report summary.

Real firmware images carry thousands of symlinks and duplicate files spread
across squashfs partitions, so the raw scanners can emit the *same* finding many
times — fifty identical ``/etc/shadow`` password-hash findings from fifty
copies of the file, for example. That volume drowns the report without adding
information.

This module is a pure post-processing pass over the already-collected
``Finding`` lists. It does two things and produces one artifact:

* **deduplicate** — collapse findings that are semantically identical (same
  category, type, severity, and per-finding identity) but appear at different
  paths into a single finding carrying a ``count`` and a sorted ``paths`` list.
* **group_binaries** — cluster binary findings by the binary they came from so
  the report can show a per-binary view alongside the flat list.
* **build_summary** — a top-level ``summary`` block with total finding counts
  broken down by severity and by category. It is the first thing an analyst
  looks at.

Everything here is dependency-free and operates on the in-memory model only; it
does not touch the filesystem or any external tool.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Report

# Severity buckets, ordered most-to-least serious. Used to give the summary a
# stable key order and to surface unknown labels under "other".
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _identity(finding: Finding) -> str:
    """A per-finding identity string used to tell duplicates apart.

    Two findings of the same category/type/severity at different paths are only
    "the same finding" if they describe the same underlying artifact. The
    discriminator differs by category:

    * credentials — the ``key`` (for hardcoded creds) or the ``detail`` (which
      carries a truncated hash / key kind) distinguishes one secret from
      another. Two ``/etc/shadow`` copies with the same hash dedup; a different
      hash does not.
    * binaries — the CWE plus the function/symbol/address it was found at.
    * certificates — the detail/reason describing *why* the cert is risky.

    Falling back to ``detail`` keeps the function total even when a category
    grows new ``extra`` fields later.
    """
    if finding.category == "credential":
        key = finding.extra.get("key")
        return key if key else finding.detail
    if finding.category == "binary":
        parts = [
            str(finding.extra.get("function") or ""),
            str(finding.extra.get("symbol") or ""),
            str(finding.extra.get("address") or ""),
        ]
        joined = "|".join(p for p in parts if p)
        return joined if joined else finding.detail
    return finding.detail


def _signature(finding: Finding) -> tuple[str, str, str, str]:
    """The full dedup signature: identical signatures collapse into one."""
    return (finding.category, finding.type, finding.severity, _identity(finding))


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings, preserving order of first appearance.

    Findings that share a :func:`_signature` are merged into the *first* one
    seen. The survivor gains a ``count`` (how many were collapsed) and a sorted,
    de-duplicated ``paths`` list of every path the finding appeared at. Its own
    ``path`` field is left untouched (it stays the first path) so existing
    consumers keep working; ``paths`` is the superset.

    A finding seen only once still gets ``count: 1`` and a single-entry
    ``paths`` list, so downstream code never has to special-case the singleton.
    """
    survivors: dict[tuple[str, str, str, str], Finding] = {}
    order: list[tuple[str, str, str, str]] = []
    paths: dict[tuple[str, str, str, str], list[str]] = {}

    for finding in findings:
        sig = _signature(finding)
        if sig not in survivors:
            survivors[sig] = finding
            order.append(sig)
            paths[sig] = []
        paths[sig].append(finding.path)

    out: list[Finding] = []
    for sig in order:
        finding = survivors[sig]
        unique_paths = sorted(set(paths[sig]))
        finding.extra["count"] = len(paths[sig])
        finding.extra["paths"] = unique_paths
        out.append(finding)
    return out


@dataclass
class BinaryGroup:
    """All binary findings discovered in a single binary."""

    path: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def group_binaries(findings: list[Finding]) -> list[BinaryGroup]:
    """Cluster binary findings by their originating binary path.

    Order is preserved by first appearance of each path so the grouped view is
    deterministic. Non-binary findings (should not normally be passed here) are
    ignored.
    """
    groups: dict[str, BinaryGroup] = {}
    order: list[str] = []
    for finding in findings:
        if finding.category != "binary":
            continue
        if finding.path not in groups:
            groups[finding.path] = BinaryGroup(path=finding.path)
            order.append(finding.path)
        groups[finding.path].findings.append(finding)
    return [groups[p] for p in order]


@dataclass
class Summary:
    """Top-level roll-up of every finding in the report."""

    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
        }


def _all_findings(report: Report) -> list[Finding]:
    out: list[Finding] = []
    for section in (report.credentials, report.certificates, report.binaries):
        if section:
            out.extend(section)
    return out


def build_summary(report: Report) -> Summary:
    """Build the report-wide :class:`Summary`.

    Counts each finding once. When findings have been deduplicated the
    collapsed ``count`` is *not* multiplied in — the summary counts distinct
    findings, which is what an analyst triages. Severities outside
    :data:`SEVERITY_ORDER` are bucketed under ``"other"``. Only severity buckets
    that actually occur appear in ``by_severity`` (kept in canonical order).
    """
    findings = _all_findings(report)

    sev_counter: Counter[str] = Counter()
    cat_counter: Counter[str] = Counter()
    for finding in findings:
        sev = finding.severity if finding.severity in SEVERITY_ORDER else "other"
        sev_counter[sev] += 1
        cat_counter[finding.category] += 1

    ordered_keys = [*SEVERITY_ORDER, "other"]
    by_severity = {k: sev_counter[k] for k in ordered_keys if sev_counter[k]}
    by_category = dict(sorted(cat_counter.items()))

    return Summary(
        total=len(findings),
        by_severity=by_severity,
        by_category=by_category,
    )


def postprocess(report: Report) -> Report:
    """Apply dedup + grouping + summary to a populated report, in place.

    This is the single entry point the pipeline calls after all checks run.
    It mutates ``report`` and returns it for convenience. Sections left as
    ``None`` (checks that did not run) are skipped, so a report is never given a
    summary for data it does not have.
    """
    if report.credentials is not None:
        report.credentials = deduplicate(report.credentials)
    if report.certificates is not None:
        report.certificates = deduplicate(report.certificates)
    if report.binaries is not None:
        report.binaries = deduplicate(report.binaries)
        report.binary_groups = group_binaries(report.binaries)

    # A summary is only meaningful if at least one finding-bearing check ran.
    if any(
        section is not None
        for section in (report.credentials, report.certificates, report.binaries)
    ):
        report.summary = build_summary(report)

    return report
