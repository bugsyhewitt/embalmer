"""SPDX relationship-graph structural validation.

embalmer *generates* an SPDX 2.3 document from its package inventory
(:meth:`embalmer.sbom.Sbom.to_spdx`) — a set of ``packages``, a set of
``relationships`` wiring them together, and a synthetic root ``firmware``
package every component CONTAINS-links to. The NTIA check
(:mod:`embalmer.ntia`) scores that document's *content* against the federal
minimum data fields; this module is its structural companion: it validates that
the emitted SPDX document is an internally-consistent **relationship graph**.

An SPDX document can carry every required field and still be a broken artifact:
a relationship can point at an ``spdxElementId`` no element declares, two
packages can collide on one ``SPDXID``, a package can be declared but never
wired into the graph (orphaned, unreachable from the document root), or the
document can fail to DESCRIBE any root at all. Strict SPDX validators (the SPDX
online validator, ntia-conformance-checker, ORT) reject such documents, and a
downstream dependency graph silently drops the unreachable nodes. embalmer
builds the graph correctly today, so this validation is a *guarantee* — it
proves the generated document is well-formed and gives a consumer a structured
pass/fail to gate on, the same way the NTIA check gives a content pass/fail.

The checks, each a graph invariant SPDX 2.3 (§6, §7, §11) requires:

    1. Document identifier  — the document declares the reserved
       ``SPDXRef-DOCUMENT`` as its own ``SPDXID``.
    2. SPDXID uniqueness    — every element's ``SPDXID`` is unique across the
       document (a duplicate makes relationship endpoints ambiguous).
    3. SPDXID well-formed    — every ``SPDXID`` matches ``SPDXRef-[A-Za-z0-9.-]+``.
    4. Relationship endpoints resolve — every ``spdxElementId`` and
       ``relatedSpdxElement`` in a relationship names a declared element (a
       package's ``SPDXID`` or the document id), i.e. no dangling edge.
    5. Document describes a root — at least one ``DESCRIBES`` relationship
       (or its inverse ``DESCRIBED_BY``) originates from / targets
       ``SPDXRef-DOCUMENT``, so the graph has an entry point.
    6. No orphaned packages  — every declared package is reachable from
       ``SPDXRef-DOCUMENT`` by following relationship edges, so nothing is
       declared-but-disconnected.

The validation is self-contained: it reads a rendered SPDX document ``dict`` (or
builds one from an :class:`~embalmer.sbom.Sbom`) and reports. It adds no
dependency and makes no network call. Structural validity is a *property of the
document* — this surfaces it explicitly.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .sbom import Sbom

# The reserved identifier the SPDX document declares for itself (SPDX 2.3 §6.3).
DOCUMENT_ID = "SPDXRef-DOCUMENT"

# A valid SPDXID is "SPDXRef-" followed by letters, numbers, ``.`` and ``-``
# (SPDX 2.3 §6.3 / §3.2). Anything else is rejected by strict validators.
_SPDXID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9.\-]+$")

# Canonical check identifiers, in the report's stable order.
DOCUMENT_IDENTIFIER = "document_identifier"
SPDXID_UNIQUE = "spdxid_unique"
SPDXID_WELL_FORMED = "spdxid_well_formed"
RELATIONSHIP_ENDPOINTS = "relationship_endpoints"
DESCRIBES_ROOT = "describes_root"
NO_ORPHAN_PACKAGES = "no_orphan_packages"

#: All checks, in canonical report order.
ALL_CHECKS: tuple[str, ...] = (
    DOCUMENT_IDENTIFIER,
    SPDXID_UNIQUE,
    SPDXID_WELL_FORMED,
    RELATIONSHIP_ENDPOINTS,
    DESCRIBES_ROOT,
    NO_ORPHAN_PACKAGES,
)

#: Human-readable label for each check.
CHECK_LABELS: dict[str, str] = {
    DOCUMENT_IDENTIFIER: "Document identifier",
    SPDXID_UNIQUE: "SPDXID uniqueness",
    SPDXID_WELL_FORMED: "SPDXID well-formed",
    RELATIONSHIP_ENDPOINTS: "Relationship endpoints resolve",
    DESCRIBES_ROOT: "Document describes a root",
    NO_ORPHAN_PACKAGES: "No orphaned packages",
}


@dataclass
class CheckResult:
    """The result of one SPDX structural check."""

    check: str
    label: str
    #: ``True`` when the document satisfies this structural invariant.
    passed: bool
    #: The element/relationship identifiers that violated the check (empty when
    #: it passed). Kept so a consumer can pinpoint *which* element is broken,
    #: not just that something is.
    offenders: list[str] = field(default_factory=list)
    #: Short human explanation of the verdict.
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "check": self.check,
            "label": self.label,
            "passed": self.passed,
            "detail": self.detail,
        }
        if self.offenders:
            out["offenders"] = list(self.offenders)
        return out


@dataclass
class SpdxValidationReport:
    """The structural-validation report for an SPDX document."""

    valid: bool
    checks: list[CheckResult] = field(default_factory=list)
    package_count: int = 0
    relationship_count: int = 0

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failures(self) -> list[str]:
        """The labels of the checks that failed (report order)."""
        return [c.label for c in self.checks if not c.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "SPDX 2.3 relationship-graph validation",
            "valid": self.valid,
            "package_count": self.package_count,
            "relationship_count": self.relationship_count,
            "checks_total": len(self.checks),
            "checks_passed": self.passed_count,
            "failed_checks": self.failures,
            "checks": [c.to_dict() for c in self.checks],
        }


def _element_ids(doc: dict[str, Any]) -> list[str]:
    """Every declared element id: the document id plus each package's SPDXID.

    The document id is always a declared element (it is the SPDXID of the
    document element itself), so relationships may legitimately reference it.
    Packages without an ``SPDXID`` key contribute the empty string, which the
    well-formed check then flags — they are *declared* (so endpoint resolution
    must account for them) but malformed.
    """
    ids = [doc.get("SPDXID", "")]
    for pkg in doc.get("packages", []):
        ids.append(pkg.get("SPDXID", ""))
    return ids


def _check_document_identifier(doc: dict[str, Any]) -> CheckResult:
    spdxid = doc.get("SPDXID", "")
    ok = spdxid == DOCUMENT_ID
    detail = (
        f"document declares the reserved {DOCUMENT_ID} identifier"
        if ok
        else f"document SPDXID is {spdxid!r}, expected {DOCUMENT_ID!r}"
    )
    return CheckResult(
        check=DOCUMENT_IDENTIFIER,
        label=CHECK_LABELS[DOCUMENT_IDENTIFIER],
        passed=ok,
        offenders=[] if ok else [spdxid or "<missing>"],
        detail=detail,
    )


def _check_spdxid_unique(ids: list[str]) -> CheckResult:
    seen: set[str] = set()
    dupes: list[str] = []
    for spdxid in ids:
        if spdxid in seen and spdxid not in dupes:
            dupes.append(spdxid)
        seen.add(spdxid)
    ok = not dupes
    detail = (
        f"all {len(ids)} element identifier(s) are unique"
        if ok
        else f"{len(dupes)} duplicate SPDXID(s): {', '.join(dupes)}"
    )
    return CheckResult(
        check=SPDXID_UNIQUE,
        label=CHECK_LABELS[SPDXID_UNIQUE],
        passed=ok,
        offenders=dupes,
        detail=detail,
    )


def _check_spdxid_well_formed(ids: list[str]) -> CheckResult:
    bad = [spdxid for spdxid in ids if not _SPDXID_RE.match(spdxid or "")]
    ok = not bad
    detail = (
        f"all {len(ids)} SPDXID(s) match SPDXRef-[A-Za-z0-9.-]+"
        if ok
        else f"{len(bad)} malformed SPDXID(s): "
        + ", ".join(repr(b) for b in bad)
    )
    return CheckResult(
        check=SPDXID_WELL_FORMED,
        label=CHECK_LABELS[SPDXID_WELL_FORMED],
        passed=ok,
        offenders=[b or "<empty>" for b in bad],
        detail=detail,
    )


def _check_relationship_endpoints(
    doc: dict[str, Any], declared: set[str]
) -> CheckResult:
    """Every relationship endpoint must name a declared element."""
    dangling: list[str] = []
    for rel in doc.get("relationships", []):
        src = rel.get("spdxElementId", "")
        dst = rel.get("relatedSpdxElement", "")
        if src not in declared:
            dangling.append(src or "<missing spdxElementId>")
        if dst not in declared:
            dangling.append(dst or "<missing relatedSpdxElement>")
    ok = not dangling
    detail = (
        f"all {len(doc.get('relationships', []))} relationship endpoint(s) "
        "resolve to declared elements"
        if ok
        else f"{len(dangling)} dangling endpoint(s): "
        + ", ".join(dict.fromkeys(dangling))  # de-dup, preserve order
    )
    return CheckResult(
        check=RELATIONSHIP_ENDPOINTS,
        label=CHECK_LABELS[RELATIONSHIP_ENDPOINTS],
        passed=ok,
        offenders=list(dict.fromkeys(dangling)),
        detail=detail,
    )


def _check_describes_root(doc: dict[str, Any]) -> CheckResult:
    """At least one DESCRIBES edge connects the document to a root element.

    SPDX 2.3 §11.2: a document must DESCRIBE the element(s) it is about. The
    inverse ``DESCRIBED_BY`` (root DESCRIBED_BY document) is equally valid, so
    both directions are accepted.
    """
    has_root = False
    for rel in doc.get("relationships", []):
        rtype = rel.get("relationshipType", "")
        src = rel.get("spdxElementId", "")
        dst = rel.get("relatedSpdxElement", "")
        if rtype == "DESCRIBES" and src == DOCUMENT_ID:
            has_root = True
            break
        if rtype == "DESCRIBED_BY" and dst == DOCUMENT_ID:
            has_root = True
            break
    detail = (
        f"document {DOCUMENT_ID} DESCRIBES a root element"
        if has_root
        else f"no DESCRIBES relationship originates from {DOCUMENT_ID}"
    )
    return CheckResult(
        check=DESCRIBES_ROOT,
        label=CHECK_LABELS[DESCRIBES_ROOT],
        passed=has_root,
        offenders=[] if has_root else [DOCUMENT_ID],
        detail=detail,
    )


def _check_no_orphan_packages(doc: dict[str, Any]) -> CheckResult:
    """Every declared package must be reachable from the document root.

    Walk the relationship graph as an undirected graph (a relationship connects
    its two endpoints regardless of direction — SPDX relationships have inverses)
    starting from ``SPDXRef-DOCUMENT``. Any package SPDXID not visited is
    declared-but-disconnected: it appears in ``packages`` but no relationship
    chain ties it to the document, so a graph consumer never sees it.
    """
    adjacency: dict[str, set[str]] = {}
    for rel in doc.get("relationships", []):
        src = rel.get("spdxElementId", "")
        dst = rel.get("relatedSpdxElement", "")
        if not src or not dst:
            continue
        adjacency.setdefault(src, set()).add(dst)
        adjacency.setdefault(dst, set()).add(src)

    reachable: set[str] = set()
    queue: deque[str] = deque([DOCUMENT_ID])
    reachable.add(DOCUMENT_ID)
    while queue:
        node = queue.popleft()
        for neighbor in adjacency.get(node, ()):
            if neighbor not in reachable:
                reachable.add(neighbor)
                queue.append(neighbor)

    pkg_ids = [p.get("SPDXID", "") for p in doc.get("packages", [])]
    orphans = [pid for pid in pkg_ids if pid and pid not in reachable]
    ok = not orphans
    detail = (
        f"all {len(pkg_ids)} package(s) are reachable from {DOCUMENT_ID}"
        if ok
        else f"{len(orphans)} orphaned package(s) unreachable from "
        f"{DOCUMENT_ID}: " + ", ".join(orphans)
    )
    return CheckResult(
        check=NO_ORPHAN_PACKAGES,
        label=CHECK_LABELS[NO_ORPHAN_PACKAGES],
        passed=ok,
        offenders=orphans,
        detail=detail,
    )


def validate_document(doc: dict[str, Any]) -> SpdxValidationReport:
    """Validate a rendered SPDX 2.3 document's relationship graph.

    ``doc`` is the ``dict`` produced by :meth:`embalmer.sbom.Sbom.to_spdx` (or
    any SPDX 2.3 JSON document of the same shape). Returns an
    :class:`SpdxValidationReport`; ``valid`` is ``True`` only when every
    structural invariant holds. A valid embalmer-generated document passes all
    six checks — the validation is a *guarantee* on the generator's output, and a
    failure means the document would be rejected by a strict SPDX validator.
    """
    ids = _element_ids(doc)
    declared = set(ids)
    results: list[CheckResult] = [
        _check_document_identifier(doc),
        _check_spdxid_unique(ids),
        _check_spdxid_well_formed(ids),
        _check_relationship_endpoints(doc, declared),
        _check_describes_root(doc),
        _check_no_orphan_packages(doc),
    ]
    valid = all(r.passed for r in results)
    return SpdxValidationReport(
        valid=valid,
        checks=results,
        package_count=len(doc.get("packages", [])),
        relationship_count=len(doc.get("relationships", [])),
    )


def validate(sbom: "Sbom", firmware: str) -> SpdxValidationReport:
    """Render ``sbom`` to an SPDX document and validate its relationship graph.

    Convenience wrapper for the pipeline: builds the SPDX document from the
    in-memory inventory (the same document the report emits under ``sbom.spdx``)
    and validates it. ``firmware`` names the BOM subject, matching
    :meth:`embalmer.sbom.Sbom.to_spdx`.
    """
    return validate_document(sbom.to_spdx(firmware))
