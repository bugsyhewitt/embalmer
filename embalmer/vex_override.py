"""VEX-override: import a VEX document and apply its assertions to scan results.

embalmer already *emits* a CycloneDX VEX document under ``--vex``
(:mod:`embalmer.vex`): the exploitability companion to the SBOM, distilled from
the binary findings' CVE evidence. This module is the inverse direction —
*importing* a VEX document and applying its per-CVE state assertions to the
``sbom.vulnerabilities`` CVE matches produced by ``--sbom-cve`` / ``--sbom-osv``.

Why this exists
---------------
A CVE cross-reference is necessarily *noisy*: NVD/OSV match every CVE that has
ever been catalogued against a CPE/purl, but a downstream firmware vendor often
has authoritative knowledge that a specific CVE does not apply
("not_affected" — the vulnerable code path is unreachable in their
configuration), is a "false_positive" (the CVE was a mismatched CPE), or is
already "fixed" in their backport. Today an operator has to read every CVE
match and decide for themselves; with this flag they hand embalmer a VEX
document and the CVE list is filtered by the vendor's own assertions before the
``--fail-on`` gate scores it.

This is the *consume* side of the VEX standard. The same CycloneDX 1.6 VEX
document embalmer emits under ``--vex`` is the format it accepts back — a
downstream pipeline (firmware vendor produces a VEX, customer feeds it into the
embalmer scan to filter the noise) is a first-class workflow.

What gets suppressed
--------------------
The CycloneDX ``analysis.state`` enum has six values; embalmer treats them as
follows when filtering the ``sbom.vulnerabilities`` CVE list:

* ``not_affected``           — suppress (vendor asserts the CVE does not apply)
* ``false_positive``         — suppress (vendor asserts CPE/purl mismatch)
* ``resolved``               — suppress (vendor asserts patched)
* ``resolved_with_pedigree`` — suppress (resolved + pedigree provided)
* ``exploitable``            — keep, but record the assertion (vendor confirms)
* ``in_triage``              — keep, but record the assertion (vendor reviewing)

``fixed`` is not in the CycloneDX 1.6 enum (it appears in OpenVEX / CSAF
profiles); when present in an imported document it is treated as ``resolved``
(synonym) for forward compatibility.

Suppression is *non-destructive*: a suppressed CVE moves out of the
``matches`` list (so the ``--fail-on`` gate does not count it) into a
``suppressed`` audit list, keyed by ``(cve_id, purl)``, with the VEX state
and justification preserved verbatim. The full CycloneDX VEX vocabulary
(``state``, ``justification``, ``response``, ``detail``) is carried through
so an auditor reading the report can see *why* each CVE was suppressed,
matching the same accountability posture the rest of embalmer takes.

What this is *not*
------------------
* **Not a binary-finding filter.** Binary findings (the CWE-detected
  vulnerability classes) carry a representative CVE for severity scoring, but
  the finding itself is a *class* of vulnerability (e.g. a strcpy site), not a
  specific CVE. A VEX assertion on the representative CVE does not mean the
  binary-finding class is absent. Filtering binary findings on a VEX-state
  match would silently suppress real findings — out of scope for this release.
* **Not a network call.** The VEX document is supplied locally; no upstream
  is contacted. Off by default, additive, no behavior change without the flag.
* **Not a re-scoring.** A kept CVE's severity is whatever ``--sbom-cve`` /
  ``--sbom-osv`` scored it as. The VEX assertion rides alongside as evidence,
  it does not raise or lower the CVSS/KEV/EPSS-derived label.

Supported document shapes
-------------------------
* **CycloneDX 1.4-1.6 VEX**: ``vulnerabilities[]`` with each entry carrying
  ``id`` (the CVE), ``analysis.state``, and optionally ``analysis.justification``
  / ``analysis.response`` / ``analysis.detail`` / ``affects[].ref`` (used to
  scope the assertion to a specific purl when present).
* **CycloneDX 1.6 inline-in-BOM**: the same ``vulnerabilities[]`` array
  embedded in a full BOM document — embalmer reads the array from wherever it
  appears under the top-level object or under ``vex`` / ``bom`` keys, mirroring
  its own emitted shape.

JSON only. YAML support is a deliberate non-goal for this release — every VEX
producer in the CycloneDX ecosystem emits JSON, and adding a YAML dependency
for the rare YAML-only producer would violate the "no new dependency" posture
the rest of the SBOM pipeline holds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .sbom_cve import CveMatch, SbomCveReport


class VexOverrideError(Exception):
    """The supplied VEX document could not be read or parsed."""


#: CycloneDX ``analysis.state`` values that suppress the CVE from the gate.
#: ``fixed`` is an OpenVEX/CSAF synonym for ``resolved`` and accepted for
#: forward compatibility.
SUPPRESSING_STATES: frozenset[str] = frozenset(
    {
        "not_affected",
        "false_positive",
        "resolved",
        "resolved_with_pedigree",
        "fixed",
    }
)

#: All CycloneDX ``analysis.state`` values embalmer recognizes (suppressing +
#: non-suppressing). A document carrying a state outside this set has its
#: assertion recorded but treated as non-suppressing (the conservative posture
#: — an unknown state is not grounds to drop a CVE from the gate).
KNOWN_STATES: frozenset[str] = SUPPRESSING_STATES | frozenset(
    {"exploitable", "in_triage"}
)


@dataclass(frozen=True)
class VexAssertion:
    """One CVE's VEX assertion, distilled from an imported VEX document.

    Carries the CycloneDX ``analysis`` block verbatim plus an optional
    ``purl`` scope (taken from ``affects[].ref`` when present). When ``purl``
    is ``None`` the assertion applies to *every* match of ``cve_id``; when
    set, it applies only to the (cve_id, purl) pair — letting one VEX
    document say "CVE-2014-0160 not_affected for our pkg:deb/openssl, but
    keep it for everything else".
    """

    cve_id: str
    state: str
    purl: str | None = None
    justification: str | None = None
    response: tuple[str, ...] = ()
    detail: str | None = None

    @property
    def suppresses(self) -> bool:
        """Whether this assertion removes the CVE from the gate's tally."""
        return self.state in SUPPRESSING_STATES

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cve_id": self.cve_id,
            "state": self.state,
            "suppresses": self.suppresses,
        }
        if self.purl is not None:
            out["purl"] = self.purl
        if self.justification:
            out["justification"] = self.justification
        if self.response:
            out["response"] = list(self.response)
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class VexOverrideReport:
    """Audit trail of how an imported VEX was applied to the CVE list."""

    #: Path of the imported VEX document, recorded so the report is auditable.
    source: str
    #: Every assertion read from the document, in input order. Includes
    #: assertions whose CVE was not in the scan (orphans) so an operator can
    #: see when a VEX file has drifted from the inventory.
    assertions: list[VexAssertion] = field(default_factory=list)
    #: Per-(cve_id, purl) suppression records. Each entry is the CVE match the
    #: assertion removed from the gate, plus the assertion that removed it.
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    #: Per-(cve_id, purl) annotation records — assertions that matched a CVE in
    #: the scan but did *not* suppress it (state=exploitable/in_triage). Kept
    #: as an audit trail so the report shows every assertion that was applied.
    annotated: list[dict[str, Any]] = field(default_factory=list)
    #: Assertions whose CVE id (and optional purl scope) did not match any CVE
    #: in the scan. Surfaced so a stale VEX file is visible, not silent.
    orphans: list[VexAssertion] = field(default_factory=list)

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)

    @property
    def annotated_count(self) -> int:
        return len(self.annotated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "assertion_count": len(self.assertions),
            "suppressed_count": self.suppressed_count,
            "annotated_count": self.annotated_count,
            "orphan_count": len(self.orphans),
            "suppressed": list(self.suppressed),
            "annotated": list(self.annotated),
            "orphans": [a.to_dict() for a in self.orphans],
        }


def _coerce_response(raw: Any) -> tuple[str, ...]:
    """The CycloneDX ``analysis.response`` array, normalized to strings."""
    if not isinstance(raw, list):
        return ()
    return tuple(str(r) for r in raw if isinstance(r, (str, int, float)))


def _scope_purl(entry: dict[str, Any]) -> str | None:
    """The ``affects[0].ref`` purl scope, or ``None`` for an unscoped assertion.

    A VEX entry without an ``affects`` block applies to every CVE-id match in
    the scan; one with an ``affects`` block applies only to matches whose
    component purl equals the ref. Multiple refs on one entry are flattened —
    the parser splits them into one :class:`VexAssertion` per ref upstream of
    this helper (see :func:`load`).
    """
    affects = entry.get("affects")
    if not isinstance(affects, list) or not affects:
        return None
    first = affects[0]
    if isinstance(first, dict):
        ref = first.get("ref")
        if isinstance(ref, str) and ref:
            return ref
    return None


def _iter_vex_entries(doc: Any) -> list[dict[str, Any]]:
    """Find the CycloneDX ``vulnerabilities[]`` array inside the document.

    embalmer accepts the array at several layouts so a consumer can hand back
    the exact JSON embalmer emitted (``vex.bom.vulnerabilities``), a bare VEX
    document (``vulnerabilities`` at the top level), or a full BOM with VEX
    embedded (``bom.vulnerabilities``) without reshaping.
    """
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get("vulnerabilities"), list):
        return [v for v in doc["vulnerabilities"] if isinstance(v, dict)]
    for key in ("vex", "bom"):
        nested = doc.get(key)
        if isinstance(nested, dict) and isinstance(nested.get("vulnerabilities"), list):
            return [v for v in nested["vulnerabilities"] if isinstance(v, dict)]
        if isinstance(nested, dict):
            for sub in ("bom", "vex"):
                deeper = nested.get(sub)
                if isinstance(deeper, dict) and isinstance(
                    deeper.get("vulnerabilities"), list
                ):
                    return [
                        v
                        for v in deeper["vulnerabilities"]
                        if isinstance(v, dict)
                    ]
    return []


def load(path: str | Path) -> list[VexAssertion]:
    """Parse a CycloneDX VEX JSON file into a list of :class:`VexAssertion`.

    A VEX entry with multiple ``affects[].ref`` purls is expanded to one
    assertion per ref (so the (cve_id, purl) scoping is symmetric on apply).
    Entries without a ``analysis.state`` are skipped — there is nothing to
    assert. Entries with an unknown state are kept (recorded verbatim) so the
    report still shows them, but they will not suppress.

    Raises:
        VexOverrideError: the file cannot be opened or is not valid JSON, or
            the document does not contain a ``vulnerabilities`` array embalmer
            can locate.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise VexOverrideError(f"could not read VEX file {p}: {exc}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VexOverrideError(f"VEX file {p} is not valid JSON: {exc}") from exc

    entries = _iter_vex_entries(doc)
    if not entries:
        raise VexOverrideError(
            f"VEX file {p} contains no `vulnerabilities` array "
            "(looked at the top level, under `vex`, and under `bom`)"
        )

    out: list[VexAssertion] = []
    for entry in entries:
        cve_id = entry.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        analysis = entry.get("analysis")
        if not isinstance(analysis, dict):
            continue
        state = analysis.get("state")
        if not isinstance(state, str) or not state:
            continue
        justification = analysis.get("justification")
        if not isinstance(justification, str):
            justification = None
        detail = analysis.get("detail")
        if not isinstance(detail, str):
            detail = None
        response = _coerce_response(analysis.get("response"))
        affects = entry.get("affects")
        scopes: list[str | None]
        if isinstance(affects, list) and affects:
            refs: list[str] = []
            for a in affects:
                if isinstance(a, dict) and isinstance(a.get("ref"), str):
                    ref = a["ref"]
                    if ref:
                        refs.append(ref)
            scopes = list(refs) if refs else [None]
        else:
            scopes = [None]
        for scope in scopes:
            out.append(
                VexAssertion(
                    cve_id=cve_id,
                    state=state,
                    purl=scope,
                    justification=justification,
                    response=response,
                    detail=detail,
                )
            )
    return out


def _match_records(
    match: "CveMatch", assertion: VexAssertion
) -> dict[str, Any]:
    """The shape recorded under ``suppressed`` / ``annotated`` for one apply."""
    return {
        "cve_id": match.cve_id,
        "purl": match.purl,
        "severity": match.severity,
        "cvss": match.cvss,
        "in_kev": match.in_kev,
        "vex": assertion.to_dict(),
    }


def apply(
    sbom_cve: "SbomCveReport", assertions: list[VexAssertion], source: str
) -> VexOverrideReport:
    """Apply a list of VEX assertions to an :class:`SbomCveReport` in place.

    For each assertion that matches a CVE in the scan (by ``cve_id`` and, when
    scoped, by ``purl``):

      * If the state is suppressing the match is *removed* from
        ``sbom_cve.matches`` (so the gate does not count it) and recorded under
        the override report's ``suppressed`` list with the assertion's
        justification, response, and detail.
      * Otherwise the match is left in place and the assertion is recorded
        under the override report's ``annotated`` list (an auditable
        "vendor reviewed, still in scope" trail).

    Assertions whose CVE id (and purl scope) match nothing in the scan are
    recorded under ``orphans`` — a stale VEX file is visible in the report,
    not silently discarded.

    The pass is order-stable: matches keep their original SBOM order, and
    assertions are visited in input order so the report's audit lists are
    deterministic for a given (scan, VEX) pair.
    """
    report = VexOverrideReport(source=source, assertions=list(assertions))

    by_cve: dict[str, list["CveMatch"]] = {}
    for m in sbom_cve.matches:
        by_cve.setdefault(m.cve_id, []).append(m)

    suppressed_ids: set[int] = set()
    for assertion in assertions:
        candidates = by_cve.get(assertion.cve_id, [])
        # Scope to the assertion's purl when set; an unscoped assertion fans
        # out to every match of the cve_id.
        scoped = [
            m for m in candidates
            if assertion.purl is None or m.purl == assertion.purl
        ]
        # Skip already-suppressed matches so a second assertion on the same
        # (cve_id, purl) does not double-record (and orphans-correctly when
        # the first assertion already drained the candidate set).
        scoped = [m for m in scoped if id(m) not in suppressed_ids]
        if not scoped:
            report.orphans.append(assertion)
            continue
        for m in scoped:
            if assertion.suppresses:
                report.suppressed.append(_match_records(m, assertion))
                suppressed_ids.add(id(m))
            else:
                report.annotated.append(_match_records(m, assertion))

    if suppressed_ids:
        sbom_cve.matches = [
            m for m in sbom_cve.matches if id(m) not in suppressed_ids
        ]
    return report
