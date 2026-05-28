"""Data models for embalmer reports.

These dataclasses define the stable shape of the structured firmware audit
report. The JSON report is a direct serialization of `Report.to_dict()`; the
markdown report renders the same data. Keeping a single source of truth here
means the two output formats can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .sbom import Sbom
    from .summary import BinaryGroup, Summary


@dataclass
class Finding:
    """A single observation surfaced by a check.

    `category` is the coarse bucket the report groups by:
        - "credential"  : a planted/hardcoded secret in the extracted tree
        - "binary"      : a CWE-style finding handed back from blight
        - "certificate" : a risky X.509 cert found in the extracted tree

    The remaining fields are intentionally loose (str/Any) so that the
    credential scanner, certificate scanner, and the blight handoff can all
    populate a uniform shape.
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
    """Result of running an extraction backend over the firmware image."""

    extraction_tree: dict[str, Any]
    file_count: int
    extraction_time_ms: int
    extract_root: str
    #: Which extraction backend actually produced this tree: "unblob" or
    #: "binwalk". With ``--extractor auto`` this records the backend that
    #: succeeded, so an analyst can see when the unblob primary fell back to
    #: binwalk.
    extractor_used: str = "unblob"

    def to_dict(self) -> dict[str, Any]:
        return {
            "extraction_tree": self.extraction_tree,
            "file_count": self.file_count,
            "extraction_time_ms": self.extraction_time_ms,
            "extract_root": self.extract_root,
            "extractor_used": self.extractor_used,
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
    certificates: list[Finding] | None = None
    binaries: list[Finding] | None = None
    #: Third-party component version findings (BusyBox, OpenSSL, …), populated
    #: by the `components` check.
    components: list[Finding] | None = None
    sbom: "Sbom | None" = None
    #: Per-binary grouping of `binaries`, populated by the post-processing pass.
    binary_groups: "list[BinaryGroup] | None" = None
    #: Report-wide finding roll-up, populated by the post-processing pass.
    summary: "Summary | None" = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "firmware": self.firmware,
            "checks": self.checks,
        }
        if self.summary is not None:
            out["summary"] = self.summary.to_dict()
        if self.extraction is not None:
            out["extraction"] = self.extraction.to_dict()
        if self.credentials is not None:
            out["credentials"] = [f.to_dict() for f in self.credentials]
        if self.certificates is not None:
            out["certificates"] = [f.to_dict() for f in self.certificates]
        if self.binaries is not None:
            out["binaries"] = [f.to_dict() for f in self.binaries]
        if self.components is not None:
            out["components"] = [f.to_dict() for f in self.components]
        if self.binary_groups is not None:
            out["binary_groups"] = [g.to_dict() for g in self.binary_groups]
        if self.sbom is not None:
            out["sbom"] = {
                **self.sbom.to_dict(),
                "bom": self.sbom.to_cyclonedx(self.firmware),
            }
        return out
