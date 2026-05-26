"""Data models for embalmer reports.

These dataclasses define the stable shape of the structured firmware audit
report. The JSON report is a direct serialization of `Report.to_dict()`; the
markdown report renders the same data. Keeping a single source of truth here
means the two output formats can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single observation surfaced by a check.

    `category` is the coarse bucket the report groups by:
        - "credential"  : a planted/hardcoded secret in the extracted tree
        - "binary"      : a CWE-style finding handed back from blight

    The remaining fields are intentionally loose (str/Any) so that both the
    credential scanner and the blight handoff can populate a uniform shape.
    """

    category: str
    path: str
    type: str
    detail: str = ""
    severity: str = "info"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "category": self.category,
            "path": self.path,
            "type": self.type,
            "detail": self.detail,
            "severity": self.severity,
        }
        if self.extra:
            out.update(self.extra)
        return out


@dataclass
class ExtractionResult:
    """Result of running unblob over the firmware image."""

    extraction_tree: dict[str, Any]
    file_count: int
    extraction_time_ms: int
    extract_root: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "extraction_tree": self.extraction_tree,
            "file_count": self.file_count,
            "extraction_time_ms": self.extraction_time_ms,
            "extract_root": self.extract_root,
        }


@dataclass
class Report:
    """The top-level firmware audit report.

    Sections are populated only for the checks that ran. A field left as
    `None` means "this check was not requested", which is distinct from a
    section that ran and found nothing (an empty list).
    """

    firmware: str
    checks: list[str]
    extraction: ExtractionResult | None = None
    credentials: list[Finding] | None = None
    binaries: list[Finding] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "firmware": self.firmware,
            "checks": self.checks,
        }
        if self.extraction is not None:
            out["extraction"] = self.extraction.to_dict()
        if self.credentials is not None:
            out["credentials"] = [f.to_dict() for f in self.credentials]
        if self.binaries is not None:
            out["binaries"] = [f.to_dict() for f in self.binaries]
        return out
