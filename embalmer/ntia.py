"""NTIA SBOM minimum-elements compliance check.

The U.S. NTIA's July 2021 report *The Minimum Elements For a Software Bill of
Materials (SBOM)* — the baseline EO-14028 references — defines seven **baseline
data fields** every SBOM must carry. Six are per-component; the seventh
(timestamp) plus the SBOM author are document-level. This module scores an
embalmer :class:`~embalmer.sbom.Sbom` against those minimum elements and emits a
structured pass/fail conformance report, so a consumer can answer "does this
BOM meet the federal minimum?" without re-deriving the rules themselves.

The seven NTIA minimum elements (NTIA 2021, §2.1 "Baseline Component
Information" plus the two automation/practice fields):

    1. Supplier Name          — who supplies the component
    2. Component Name          — the name of the component
    3. Version of the Component
    4. Other Unique Identifiers — a machine-readable id (purl / CPE)
    5. Dependency Relationship  — how the component relates to the whole
    6. Author of SBOM Data      — who produced the SBOM (document-level)
    7. Timestamp                — when the SBOM was produced (document-level)

embalmer's BOM is generated, not transcribed, so the document-level elements
(Author, Timestamp) and Dependency Relationship are *always* satisfied — the
CycloneDX/SPDX renderers stamp an author tool, a timestamp, and a
firmware→component relationship on every document. The per-component elements
(Supplier, Name, Version, Unique Identifier) are scored against the actual
inventory: every component carries a name, version, and a purl unique
identifier by construction, and ``supplier`` is the one element embalmer cannot
assert from firmware (it emits the ``NOASSERTION`` sentinel), so the check
honestly reports the supplier gap rather than claiming false completeness.

The check is self-contained: it reads the in-memory ``Sbom`` and reports. It
adds no dependency and makes no network call. NTIA conformance is a *property of
the document* — this surfaces it explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .sbom import Component, Sbom

# The seven NTIA minimum elements, in the report's canonical order. The
# ``level`` distinguishes a per-component field (scored against every component)
# from a document-level field (a single yes/no for the whole BOM).
SUPPLIER_NAME = "supplier_name"
COMPONENT_NAME = "component_name"
COMPONENT_VERSION = "component_version"
UNIQUE_IDENTIFIER = "unique_identifier"
DEPENDENCY_RELATIONSHIP = "dependency_relationship"
SBOM_AUTHOR = "sbom_author"
TIMESTAMP = "timestamp"

#: Per-component minimum elements — scored once per component.
COMPONENT_ELEMENTS: tuple[str, ...] = (
    SUPPLIER_NAME,
    COMPONENT_NAME,
    COMPONENT_VERSION,
    UNIQUE_IDENTIFIER,
)

#: Document-level minimum elements — a single pass/fail for the whole BOM.
DOCUMENT_ELEMENTS: tuple[str, ...] = (
    DEPENDENCY_RELATIONSHIP,
    SBOM_AUTHOR,
    TIMESTAMP,
)

#: All seven, in canonical report order.
ALL_ELEMENTS: tuple[str, ...] = COMPONENT_ELEMENTS + DOCUMENT_ELEMENTS

#: Human-readable label for each element (the NTIA field name).
ELEMENT_LABELS: dict[str, str] = {
    SUPPLIER_NAME: "Supplier Name",
    COMPONENT_NAME: "Component Name",
    COMPONENT_VERSION: "Version of the Component",
    UNIQUE_IDENTIFIER: "Other Unique Identifiers",
    DEPENDENCY_RELATIONSHIP: "Dependency Relationship",
    SBOM_AUTHOR: "Author of SBOM Data",
    TIMESTAMP: "Timestamp",
}

#: The SPDX/CycloneDX "not determined" sentinel embalmer emits when it cannot
#: assert a value (notably ``supplier``). A field holding only this sentinel is
#: present-but-unasserted, which NTIA treats as NOT satisfying the element.
NOASSERTION = "NOASSERTION"


def _component_has_supplier(comp: "Component") -> bool:
    """Whether a component carries an asserted (non-sentinel) supplier.

    embalmer inventories firmware and cannot resolve the upstream supplier of a
    package, so it emits the ``NOASSERTION`` sentinel — which NTIA counts as the
    element *not* being met. A component is only credited with a supplier when a
    real value is present.
    """
    supplier = getattr(comp, "supplier", None)
    return bool(supplier) and supplier != NOASSERTION


def _component_element_met(comp: "Component", element: str) -> bool:
    """Whether a single component satisfies a per-component NTIA element."""
    if element == SUPPLIER_NAME:
        return _component_has_supplier(comp)
    if element == COMPONENT_NAME:
        return bool(comp.name)
    if element == COMPONENT_VERSION:
        return bool(comp.version)
    if element == UNIQUE_IDENTIFIER:
        # A purl is always constructed; a CPE is an additional identifier. Either
        # is a machine-readable unique id, satisfying NTIA element 4.
        return bool(comp.purl()) or bool(comp.cpe)
    raise ValueError(f"not a per-component element: {element!r}")


@dataclass
class ElementResult:
    """Conformance result for one NTIA minimum element."""

    element: str
    label: str
    #: ``True`` when every applicable component (per-component element) or the
    #: document (document-level element) satisfies the field.
    satisfied: bool
    #: For per-component elements: how many components satisfy the field and how
    #: many were checked. ``None`` for document-level elements.
    components_satisfied: int | None = None
    components_total: int | None = None
    #: Short human explanation of the verdict.
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "element": self.element,
            "label": self.label,
            "satisfied": self.satisfied,
            "detail": self.detail,
        }
        if self.components_total is not None:
            out["components_satisfied"] = self.components_satisfied
            out["components_total"] = self.components_total
        return out


@dataclass
class NtiaReport:
    """The NTIA minimum-elements conformance report for an SBOM."""

    compliant: bool
    elements: list[ElementResult] = field(default_factory=list)
    component_count: int = 0

    @property
    def satisfied_count(self) -> int:
        return sum(1 for e in self.elements if e.satisfied)

    @property
    def missing(self) -> list[str]:
        """The labels of the elements that are not satisfied (report order)."""
        return [e.label for e in self.elements if not e.satisfied]

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "NTIA Minimum Elements (July 2021)",
            "compliant": self.compliant,
            "component_count": self.component_count,
            "elements_total": len(self.elements),
            "elements_satisfied": self.satisfied_count,
            "missing_elements": self.missing,
            "elements": [e.to_dict() for e in self.elements],
        }


def _component_element_result(comp_list: list["Component"], element: str) -> ElementResult:
    label = ELEMENT_LABELS[element]
    total = len(comp_list)
    satisfied_n = sum(1 for c in comp_list if _component_element_met(c, element))
    # An element is satisfied for the document only when EVERY component carries
    # it — NTIA conformance is all-or-nothing per element (a BOM with one
    # version-less component does not meet "Version of the Component").
    satisfied = total > 0 and satisfied_n == total
    if total == 0:
        # No components: the per-component element is vacuously not-asserted. A
        # BOM with no components cannot demonstrate the per-component minimums.
        detail = "no components in the SBOM to carry this element"
    elif satisfied:
        detail = f"all {total} component(s) carry {label.lower()}"
    elif element == SUPPLIER_NAME:
        detail = (
            f"{satisfied_n}/{total} component(s) carry an asserted supplier; "
            "embalmer inventories firmware and emits NOASSERTION where the "
            "upstream supplier cannot be determined"
        )
    else:
        detail = f"{satisfied_n}/{total} component(s) carry {label.lower()}"
    return ElementResult(
        element=element,
        label=label,
        satisfied=satisfied,
        components_satisfied=satisfied_n,
        components_total=total,
        detail=detail,
    )


def _document_element_result(element: str) -> ElementResult:
    """Score a document-level element.

    Every embalmer-generated BOM stamps these by construction, so they are
    always satisfied: the CycloneDX/SPDX renderers emit a creator/author tool, a
    creation timestamp, and a firmware→component relationship on every document.
    """
    label = ELEMENT_LABELS[element]
    detail = {
        DEPENDENCY_RELATIONSHIP: (
            "firmware->component relationships are emitted on every document "
            "(CycloneDX metadata.component / SPDX CONTAINS relationships)"
        ),
        SBOM_AUTHOR: (
            "the generating tool (embalmer / necromancer) is recorded as the "
            "SBOM author on every document"
        ),
        TIMESTAMP: "a UTC creation timestamp is stamped on every document",
    }[element]
    return ElementResult(element=element, label=label, satisfied=True, detail=detail)


def check(sbom: "Sbom") -> NtiaReport:
    """Score an :class:`~embalmer.sbom.Sbom` against the NTIA minimum elements.

    Returns an :class:`NtiaReport`. ``compliant`` is ``True`` only when all
    seven minimum elements are satisfied — which, for an embalmer BOM, requires
    every component to carry an asserted supplier. Since embalmer emits
    ``NOASSERTION`` for the supplier it cannot resolve from firmware, a typical
    real-firmware BOM is reported as non-compliant on exactly the Supplier Name
    element, honestly surfacing the one gap rather than overclaiming.
    """
    components = list(sbom.components)
    results: list[ElementResult] = []
    for element in COMPONENT_ELEMENTS:
        results.append(_component_element_result(components, element))
    for element in DOCUMENT_ELEMENTS:
        results.append(_document_element_result(element))
    compliant = all(r.satisfied for r in results)
    return NtiaReport(
        compliant=compliant,
        elements=results,
        component_count=len(components),
    )
