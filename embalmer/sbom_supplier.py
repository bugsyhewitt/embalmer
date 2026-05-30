"""SBOM supplier-metadata compliance check.

The SBOM lists every third-party component embalmer recovers from a firmware
image. Each component carries an optional ``supplier`` field — the
project/organization that ships the upstream library. Supplier metadata is the
spine of supply-chain accountability: without it, a downstream consumer has no
way to know *who* to ask when a CVE drops, no way to verify provenance against a
trusted publisher list, and no way to satisfy the procurement question

    *"Are we shipping components from suppliers we have not vetted?"*

The NTIA minimum-elements check (``--sbom-ntia-check``) already counts the
supplier element as one of seven aggregate conformance fields, but it folds the
supplier verdict into a single yes/no element alongside name, version,
identifier, dependency-relationship, author, and timestamp. The aggregate
posture is honest but coarse: an operator who only cares about supplier
provenance has to parse the NTIA report and dig out per-component supplier
gaps from a structure that was not designed to surface them.

This module is the supplier-focused gate. It is the metadata-transparency
companion to the procurement gates already shipped:

  * ``--sbom-license-check``       — gates on *what license a component carries*;
  * ``--component-blocklist``      — gates on *which component is shipping*;
  * ``--sbom-supplier-check`` (this) — gates on *who supplied each component*.

The verdict is a per-component pass/fail under a new ``sbom.suppliers`` report
key: every SBOM component is recorded with ``has_supplier: true/false`` for
uniform downstream consumption (the same shape ``sbom.component_blocklist``
uses for its blocked/allowed verdict). Components carrying an asserted supplier
(non-empty, non-``NOASSERTION``) pass; components with an empty or
``NOASSERTION`` supplier fail. The overall ``compliant`` boolean is ``True``
when every component carries a supplier.

Why a separate flag rather than just reading the NTIA report?

  1. **Targeted CI**: an operator who only enforces supplier provenance does not
     want to opt into the full NTIA gate (which scores six other fields too)
     and have ``--fail-on`` trip on, say, a missing document-level timestamp.
     The supplier-check is a single-axis policy with its own ``--fail-on``
     composition.
  2. **Per-component verdicts**: the NTIA report records the aggregate count
     ("3 of 12 components carry an asserted supplier") but not which specific
     components failed. The supplier-check records each component verbatim so
     CI logs and downstream tooling can list the offenders.
  3. **Honest posture preserved**: components embalmer cannot resolve a supplier
     for (typically package-database components — dpkg/opkg/apk) keep the
     ``NOASSERTION`` sentinel, and this gate counts that as a fail. embalmer
     does NOT invent a supplier value to make the gate pass — overclaiming the
     supplier is the failure mode the supply-chain community is trying to avoid.

Self-contained: no network call, no new dependency, reads the in-memory
:class:`~embalmer.sbom.Sbom`. Off by default — every existing report path is
byte-for-byte unchanged. Composes with ``--fail-on`` (R31): each missing
supplier is scored at the ``medium`` severity tier and counted by the gate, so

    ``--sbom-supplier-check --fail-on medium``

fails the build with exit code 10 when any component lacks a supplier, without
the operator having to parse the JSON verdict themselves. The ``medium`` tier
sits below ``--component-blocklist``'s ``high`` (a metadata-transparency gap
is a weaker fail signal than a procurement-policy violation) and above the
information-only license categorization, putting the supplier gate on the same
ladder rung as a non-KEV / low-EPSS CVE — a real signal CI should surface, but
not as severe as an actively exploited vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .ntia import NOASSERTION

if TYPE_CHECKING:
    from .sbom import Component, Sbom


#: Severity assigned to each component missing a supplier for the ``--fail-on``
#: gate. ``medium`` is the right tier: a missing supplier is a real
#: supply-chain-transparency gap (the consumer cannot ask anyone about a CVE),
#: but it is weaker than a procurement-policy violation (``--component-blocklist``
#: at ``high``) — the component is allowed by policy, the *metadata* is
#: incomplete.
MISSING_SUPPLIER_SEVERITY = "medium"


def _component_has_supplier(comp: "Component") -> bool:
    """Whether a component carries an asserted (non-sentinel) supplier.

    A component passes the supplier check only when its ``supplier`` field is a
    non-empty string that is not the ``NOASSERTION`` sentinel. embalmer emits
    ``NOASSERTION`` for components whose upstream supplier it cannot resolve
    from firmware (package-database components, typically); those count as fail
    here just as they do under NTIA element 1.
    """
    supplier = getattr(comp, "supplier", None)
    return bool(supplier) and supplier != NOASSERTION


@dataclass
class SupplierComponent:
    """A per-component supplier verdict."""

    purl: str
    name: str
    version: str
    #: The supplier value verbatim from the SBOM component, or ``None`` when the
    #: component carried no supplier at all (distinct from a ``NOASSERTION``
    #: sentinel string). Preserved in the report so an auditor can see exactly
    #: what the SBOM declared.
    supplier: str | None

    @property
    def has_supplier(self) -> bool:
        """Whether this component carries an asserted supplier (the verdict)."""
        if self.supplier is None:
            return False
        return self.supplier != "" and self.supplier != NOASSERTION

    @property
    def severity(self) -> str | None:
        """Severity tier the ``--fail-on`` gate counts this verdict at.

        Components missing a supplier are scored at
        :data:`MISSING_SUPPLIER_SEVERITY`; components with an asserted supplier
        carry no severity (they do not appear in the gate's tally). Returned as
        ``None`` for compliant components so the report consumer can dispatch on
        presence.
        """
        return None if self.has_supplier else MISSING_SUPPLIER_SEVERITY

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "purl": self.purl,
            "name": self.name,
            "version": self.version,
            "supplier": self.supplier,
            "has_supplier": self.has_supplier,
        }
        if not self.has_supplier:
            out["severity"] = MISSING_SUPPLIER_SEVERITY
        return out


@dataclass
class SbomSupplierReport:
    """SBOM supplier-metadata compliance report."""

    #: Overall verdict: ``True`` when every component carries an asserted
    #: supplier. An empty SBOM trivially passes (vacuously compliant — no
    #: component fails the check) which matches the posture
    #: :class:`~embalmer.component_blocklist.ComponentBlocklistReport` takes for
    #: the symmetric "no components, no violations" case.
    compliant: bool
    #: Per-component verdicts, in the SBOM's component order.
    components: list[SupplierComponent] = field(default_factory=list)

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def missing_components(self) -> list[SupplierComponent]:
        """Per-component verdicts that lack an asserted supplier."""
        return [c for c in self.components if not c.has_supplier]

    @property
    def asserted_count(self) -> int:
        """How many components carry an asserted supplier."""
        return sum(1 for c in self.components if c.has_supplier)

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "SBOM supplier-metadata compliance",
            "compliant": self.compliant,
            "component_count": self.component_count,
            "asserted_count": self.asserted_count,
            "missing_count": len(self.missing_components),
            "components": [c.to_dict() for c in self.components],
        }


def check(sbom: "Sbom") -> SbomSupplierReport:
    """Score an :class:`~embalmer.sbom.Sbom` for supplier-metadata completeness.

    Every component in the SBOM is recorded with a per-component verdict; the
    overall ``compliant`` boolean is ``True`` when every component carries an
    asserted supplier (non-empty, non-``NOASSERTION``).
    """
    components: list[SupplierComponent] = []
    for comp in sbom.components:
        components.append(
            SupplierComponent(
                purl=comp.purl(),
                name=comp.name,
                version=comp.version,
                supplier=comp.supplier,
            )
        )
    compliant = all(c.has_supplier for c in components)
    return SbomSupplierReport(compliant=compliant, components=components)
