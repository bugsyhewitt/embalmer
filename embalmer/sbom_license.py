"""SBOM license-policy compliance check.

The SBOM already records each component's declared license (the dpkg ``License:``
field, the apk ``L:`` field, …) and renders it spec-correctly into CycloneDX /
SPDX (see :mod:`embalmer.licenses` for the validation/canonicalization pipeline
shipped in Phase 2 Rotation 23). What the SBOM does **not** do is *score* those
licenses against a policy — and a license inventory is only useful as a
compliance signal when paired with one.

This module is the policy-side companion to the existing license-validation
pipeline. It walks an :class:`~embalmer.sbom.Sbom` and:

  * **categorizes** every component's declared license into a coarse bucket the
    way real legal/procurement teams think about it — *permissive*,
    *weak-copyleft*, *strong-copyleft*, *network-copyleft*, *public-domain*,
    *other*, *unknown*, or *noassertion*; and
  * **scores** the inventory against an optional disallow-list of SPDX
    identifiers (``--disallow-license AGPL-3.0-only --disallow-license …``) —
    a component declaring a disallowed license fails the gate, and the verdict
    rides under a new ``sbom.licenses`` report key the CI severity gate (R31's
    ``--fail-on``) and any downstream tooling can act on.

Why this is the right next step:

  * **License-compliance is the #2 SBOM use-case after vuln matching** (NTIA
    *Minimum Elements*, §3.2; the SPDX charter exists for license tracking,
    not vuln data). A firmware SBOM that doesn't surface a license posture is
    half-useful.
  * **It is self-contained** — no network call, no new dependency, reuses the
    already-shipped :mod:`embalmer.licenses` SPDX validator/canonicalizer.
  * **It composes with the existing CI gate** — the structured pass/fail report
    follows the exact shape of NTIA / SPDX-validation / purl-validation, so the
    consumer pattern (a JSON-readable verdict + a one-line summary) is uniform.
  * **It is honest by construction** — a component with ``None`` /
    ``NOASSERTION`` declared license is reported as such rather than silently
    treated as compliant or non-compliant; the verdict says *what the firmware
    declared*, not what embalmer wishes it had.

The categorization set is deliberately small — embalmer is a firmware analyzer,
not a license scanner — and covers the SPDX identifiers that actually appear in
Linux firmware package databases (the same set :mod:`embalmer.licenses`
curates). An identifier outside the set is classified as ``other`` rather than
guessed at; the disallow-list still matches by exact (canonical) id, so a
policy can disallow an ``other``-bucket id and the gate honors it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import licenses

if TYPE_CHECKING:
    from .sbom import Component, Sbom

# License categories. The set is the coarse bucket a legal/procurement team
# triages by; the per-id mapping below assigns every curated SPDX identifier to
# one of these. Categories outside the firmware set use ``CATEGORY_OTHER``.
CATEGORY_PERMISSIVE = "permissive"
CATEGORY_WEAK_COPYLEFT = "weak-copyleft"
CATEGORY_STRONG_COPYLEFT = "strong-copyleft"
CATEGORY_NETWORK_COPYLEFT = "network-copyleft"
CATEGORY_PUBLIC_DOMAIN = "public-domain"
CATEGORY_OTHER = "other"
CATEGORY_UNKNOWN = "unknown"
CATEGORY_NOASSERTION = "noassertion"

#: All categories, in canonical report order.
ALL_CATEGORIES: tuple[str, ...] = (
    CATEGORY_PERMISSIVE,
    CATEGORY_WEAK_COPYLEFT,
    CATEGORY_STRONG_COPYLEFT,
    CATEGORY_NETWORK_COPYLEFT,
    CATEGORY_PUBLIC_DOMAIN,
    CATEGORY_OTHER,
    CATEGORY_UNKNOWN,
    CATEGORY_NOASSERTION,
)

# Curated SPDX-id -> category map for the licenses :mod:`embalmer.licenses`
# recognizes. Lookup is by canonical (spec-cased) SPDX id; the caller
# canonicalizes the declared string through :func:`licenses.canonicalize_expression`
# first, so case-variant declarations (``mit`` vs. ``MIT``) hit the same entry.
_CATEGORY_BY_ID: dict[str, str] = {
    # permissive
    "MIT": CATEGORY_PERMISSIVE,
    "MIT-0": CATEGORY_PERMISSIVE,
    "BSD-2-Clause": CATEGORY_PERMISSIVE,
    "BSD-3-Clause": CATEGORY_PERMISSIVE,
    "BSD-4-Clause": CATEGORY_PERMISSIVE,
    "0BSD": CATEGORY_PERMISSIVE,
    "ISC": CATEGORY_PERMISSIVE,
    "Apache-2.0": CATEGORY_PERMISSIVE,
    "Apache-1.1": CATEGORY_PERMISSIVE,
    "Zlib": CATEGORY_PERMISSIVE,
    "libpng-2.0": CATEGORY_PERMISSIVE,
    "X11": CATEGORY_PERMISSIVE,
    "Unlicense": CATEGORY_PERMISSIVE,
    "WTFPL": CATEGORY_PERMISSIVE,
    "BSL-1.0": CATEGORY_PERMISSIVE,
    "Python-2.0": CATEGORY_PERMISSIVE,
    "PSF-2.0": CATEGORY_PERMISSIVE,
    "OpenSSL": CATEGORY_PERMISSIVE,
    "curl": CATEGORY_PERMISSIVE,
    "NCSA": CATEGORY_PERMISSIVE,
    "Beerware": CATEGORY_PERMISSIVE,
    # strong copyleft (file-level copyleft for the GPL family)
    "GPL-2.0-only": CATEGORY_STRONG_COPYLEFT,
    "GPL-2.0-or-later": CATEGORY_STRONG_COPYLEFT,
    "GPL-3.0-only": CATEGORY_STRONG_COPYLEFT,
    "GPL-3.0-or-later": CATEGORY_STRONG_COPYLEFT,
    # weak copyleft (library/file-level copyleft, dynamic-link safe)
    "LGPL-2.0-only": CATEGORY_WEAK_COPYLEFT,
    "LGPL-2.0-or-later": CATEGORY_WEAK_COPYLEFT,
    "LGPL-2.1-only": CATEGORY_WEAK_COPYLEFT,
    "LGPL-2.1-or-later": CATEGORY_WEAK_COPYLEFT,
    "LGPL-3.0-only": CATEGORY_WEAK_COPYLEFT,
    "LGPL-3.0-or-later": CATEGORY_WEAK_COPYLEFT,
    "MPL-1.1": CATEGORY_WEAK_COPYLEFT,
    "MPL-2.0": CATEGORY_WEAK_COPYLEFT,
    "EPL-1.0": CATEGORY_WEAK_COPYLEFT,
    "EPL-2.0": CATEGORY_WEAK_COPYLEFT,
    "CDDL-1.0": CATEGORY_WEAK_COPYLEFT,
    "CDDL-1.1": CATEGORY_WEAK_COPYLEFT,
    "Artistic-1.0": CATEGORY_WEAK_COPYLEFT,
    "Artistic-2.0": CATEGORY_WEAK_COPYLEFT,
    # network copyleft — the AGPL family triggers source-disclosure even for
    # network-only use, the famous SaaS-incompatible case legal teams gate on
    "AGPL-3.0-only": CATEGORY_NETWORK_COPYLEFT,
    "AGPL-3.0-or-later": CATEGORY_NETWORK_COPYLEFT,
    # public-domain dedications and CC-* attribution licenses
    "CC0-1.0": CATEGORY_PUBLIC_DOMAIN,
    "CC-BY-3.0": CATEGORY_PUBLIC_DOMAIN,
    "CC-BY-4.0": CATEGORY_PUBLIC_DOMAIN,
    "CC-BY-SA-3.0": CATEGORY_PUBLIC_DOMAIN,
    "CC-BY-SA-4.0": CATEGORY_PUBLIC_DOMAIN,
    # the SPDX sentinels
    "NONE": CATEGORY_PUBLIC_DOMAIN,  # spec: "no license declared by the author"
    "NOASSERTION": CATEGORY_NOASSERTION,
}

#: Human-readable label for each category.
CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_PERMISSIVE: "permissive",
    CATEGORY_WEAK_COPYLEFT: "weak copyleft",
    CATEGORY_STRONG_COPYLEFT: "strong copyleft",
    CATEGORY_NETWORK_COPYLEFT: "network copyleft (AGPL)",
    CATEGORY_PUBLIC_DOMAIN: "public domain",
    CATEGORY_OTHER: "other (recognized SPDX id outside the firmware bucket map)",
    CATEGORY_UNKNOWN: "unknown (non-SPDX or unparseable)",
    CATEGORY_NOASSERTION: "noassertion (declared no value)",
}


# --- license expression extraction -----------------------------------------


def _extract_ids(expr: str) -> list[str]:
    """Return the SPDX license identifiers (canonical-cased) appearing in ``expr``.

    A compound expression like ``MIT OR GPL-2.0-only`` contributes both ids.
    A ``LicenseRef``-style atom contributes nothing (it does not name a SPDX
    identifier the policy can score against). Operators and parentheses are
    skipped. An empty / un-tokenizable expression returns an empty list.

    Canonicalization runs first, so a declaration of ``mit OR gpl-2.0-only``
    yields ``["MIT", "GPL-2.0-only"]`` regardless of source case.
    """
    if not expr:
        return []
    canon = licenses.canonicalize_expression(expr)
    out: list[str] = []
    for tok in canon.split():
        if tok in ("AND", "OR", "WITH", "(", ")"):
            continue
        # Strip parentheses that abut an atom (``(MIT`` -> ``MIT``).
        tok = tok.strip("()")
        if not tok:
            continue
        # Skip LicenseRef / DocumentRef atoms — they do not name a SPDX id.
        if tok.startswith(("LicenseRef-", "DocumentRef-")):
            continue
        # Skip exception identifiers appearing after WITH; the tokenizer above
        # already removed the WITH keyword, but a bare exception id is not a
        # license id and should not be scored.
        if tok in licenses._SPDX_EXCEPTIONS.values():
            continue
        # Strip the SPDX "or-later" ``+`` shorthand for category lookup.
        bare = tok[:-1] if tok.endswith("+") else tok
        out.append(bare)
    return out


def categorize(expr: str | None) -> str:
    """Return the policy category for a declared license expression.

    Decision order:

      * ``None`` or the empty string -> :data:`CATEGORY_NOASSERTION`
        (nothing declared);
      * the ``NOASSERTION`` sentinel -> :data:`CATEGORY_NOASSERTION`;
      * a non-SPDX or unparseable expression -> :data:`CATEGORY_UNKNOWN`
        (the same string :mod:`embalmer.licenses` routes through the
        ``LicenseRef`` escape hatch);
      * a single recognized id -> its mapped category;
      * a compound expression -> the **strictest** category among its atoms
        (where strictness is the order in :data:`ALL_CATEGORIES`, network
        copyleft > strong > weak > permissive, so ``MIT OR AGPL-3.0-only``
        classifies as ``network-copyleft``).

    The "strictest wins" rule is the conservative choice for a compliance
    gate: a component offered under MIT *or* AGPL still carries the AGPL
    obligation if the consumer picks that branch, so the inventory must
    surface the strictest option.
    """
    if expr is None or expr.strip() == "":
        return CATEGORY_NOASSERTION
    if not licenses.is_valid_expression(expr):
        return CATEGORY_UNKNOWN
    ids = _extract_ids(expr)
    if not ids:
        # Valid expression of only LicenseRef atoms -> still unknown to the
        # policy (the SPDX escape hatch records a non-SPDX license).
        return CATEGORY_UNKNOWN
    # Strictness rank: lower index in this tuple = stricter. The order here is
    # deliberately *not* ALL_CATEGORIES (which is report order); it is the
    # compliance-strictness order.
    strictness = (
        CATEGORY_NETWORK_COPYLEFT,
        CATEGORY_STRONG_COPYLEFT,
        CATEGORY_WEAK_COPYLEFT,
        CATEGORY_OTHER,
        CATEGORY_PERMISSIVE,
        CATEGORY_PUBLIC_DOMAIN,
    )
    rank = {cat: i for i, cat in enumerate(strictness)}
    cats = [_CATEGORY_BY_ID.get(i, CATEGORY_OTHER) for i in ids]
    return min(cats, key=lambda c: rank.get(c, len(strictness)))


# --- per-component result and overall report -------------------------------


@dataclass
class ComponentLicense:
    """The license verdict for a single SBOM component."""

    #: Component identity for the verdict (the same purl the SBOM emits).
    purl: str
    name: str
    version: str
    #: The declared license string verbatim from the package database, or
    #: ``None`` when the database carried no value.
    declared: str | None
    #: Policy category — one of :data:`ALL_CATEGORIES`.
    category: str
    #: Canonical (spec-cased) SPDX identifiers extracted from the expression
    #: (empty for noassertion / unknown / LicenseRef-only).
    ids: list[str] = field(default_factory=list)
    #: Disallow-list ids matched by this component (subset of :attr:`ids`)
    #: that were **not** exempted by a ``--license-exception`` for this
    #: component. A non-empty list means the component fails the policy.
    disallowed: list[str] = field(default_factory=list)
    #: Disallow-list ids matched by this component that were **exempted** by a
    #: ``--license-exception NAME:SPDX_ID`` rule naming this component. These
    #: ids would otherwise have landed in :attr:`disallowed` and failed the
    #: policy; the exception cleared them. Recorded for auditability — the
    #: consumer can see *which* component-specific waivers were applied.
    exempted: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        """Whether this component passes the disallow policy.

        A component with no disallowed ids passes; a component with any
        disallowed id fails. Noassertion / unknown components pass the
        disallow policy (a missing license cannot be on the disallow list);
        they are surfaced separately via the report's category counts so the
        consumer can decide whether to fail closed on those too. An
        exempted id (see :attr:`exempted`) does not count against the
        component — the exception cleared it.
        """
        return not self.disallowed

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "purl": self.purl,
            "name": self.name,
            "version": self.version,
            "declared": self.declared,
            "category": self.category,
            "ids": list(self.ids),
            "allowed": self.allowed,
        }
        if self.disallowed:
            out["disallowed"] = list(self.disallowed)
        if self.exempted:
            out["exempted"] = list(self.exempted)
        return out


@dataclass
class SbomLicenseReport:
    """The license-policy compliance report for an SBOM."""

    #: Overall verdict: ``True`` when no component matched the disallow policy.
    #: A report with no disallow list always reports ``compliant=True``
    #: (informational-only mode).
    compliant: bool
    #: Disallow-list policy (canonical SPDX ids) the report was scored against.
    disallow: list[str] = field(default_factory=list)
    #: Per-component disallow-policy exceptions the report was scored against,
    #: canonicalized to ``"<name>:<SPDX_ID>"`` (lowercased name, canonical
    #: SPDX id), in input order with duplicates removed. An exception waives
    #: a single (component name, license id) pair from the disallow policy
    #: — e.g. ``mongodb:AGPL-3.0-only`` allows AGPL-3.0-only specifically on
    #: ``mongodb`` while still failing AGPL elsewhere.
    exceptions: list[str] = field(default_factory=list)
    #: Per-component verdicts, in the SBOM's component order.
    components: list[ComponentLicense] = field(default_factory=list)
    #: Component counts by category (every category in ``ALL_CATEGORIES``
    #: appears, possibly zero — uniform shape for downstream consumers).
    category_counts: dict[str, int] = field(default_factory=dict)

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def disallowed_components(self) -> list[ComponentLicense]:
        """Per-component verdicts that matched the disallow policy."""
        return [c for c in self.components if not c.allowed]

    @property
    def exempted_components(self) -> list[ComponentLicense]:
        """Per-component verdicts where an exception cleared at least one id."""
        return [c for c in self.components if c.exempted]

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "standard": "SPDX license-policy compliance",
            "compliant": self.compliant,
            "disallow": list(self.disallow),
            "component_count": self.component_count,
            "disallowed_component_count": len(self.disallowed_components),
            "category_counts": dict(self.category_counts),
            "components": [c.to_dict() for c in self.components],
        }
        # Only surface the exceptions key when one was configured — keeps the
        # JSON shape byte-for-byte unchanged for every existing caller that
        # never passes --license-exception.
        if self.exceptions:
            out["exceptions"] = list(self.exceptions)
            out["exempted_component_count"] = len(self.exempted_components)
        return out


# --- public entry points ---------------------------------------------------


def _canonicalize_disallow(disallow: list[str] | None) -> list[str]:
    """Canonicalize a user-supplied disallow list to canonical SPDX ids.

    A user may pass ``--disallow-license gpl-3.0-only`` (case-variant); we
    look it up against :data:`embalmer.licenses._SPDX_LICENSES` so the
    matching downstream is exact. An id not recognized as SPDX is kept
    verbatim — the consumer may want to disallow a string that
    :mod:`embalmer.licenses` would route through ``LicenseRef``.
    """
    if not disallow:
        return []
    out: list[str] = []
    for raw in disallow:
        token = raw.strip()
        if not token:
            continue
        canon = licenses._canonical_id(token)
        out.append(canon if canon is not None else token)
    return out


class ExceptionParseError(ValueError):
    """Raised when ``--license-exception`` cannot be parsed.

    The CLI catches this and converts it into a usage error (exit 2) so the
    user sees the exact bad token rather than a Python traceback.
    """


def _parse_exceptions(exceptions: list[str] | None) -> tuple[dict[str, set[str]], list[str]]:
    """Parse the user-supplied exception rules into a lookup + canonical list.

    Each input token is ``"<name>:<spdx-id>"``. ``<name>`` matches the
    component's ``name`` field case-insensitively (the SBOM stores package
    names verbatim, which for dpkg/opkg/apk is the lowercase package id, but
    binary-detected components carry the CPE vendor casing; case-insensitive
    matching covers both honestly without forcing the user to know the
    upstream casing). ``<spdx-id>`` is canonicalized to the spec-cased SPDX
    identifier the same way ``--disallow-license`` is, so a user can pass
    ``mongodb:agpl-3.0-only`` and have it match the canonical
    ``AGPL-3.0-only`` extracted from the inventory.

    Returns ``(lookup, canonical)`` where:

      * ``lookup`` maps the lowercased component name to the set of canonical
        SPDX ids exempted for it;
      * ``canonical`` is the input list deduplicated and rendered in
        canonical ``"<name>:<spdx-id>"`` form (lowercased name, canonical id),
        preserving first-seen order. The list is the value surfaced under
        ``sbom.licenses.exceptions`` in the report.

    A token missing the ``:`` separator, with an empty name, or with an empty
    id raises :class:`ExceptionParseError`. An ``<spdx-id>`` not recognized as
    SPDX is kept verbatim (mirroring the ``--disallow-license`` convention so
    a consumer can exempt a string that routes through ``LicenseRef``).
    """
    if not exceptions:
        return {}, []
    lookup: dict[str, set[str]] = {}
    canonical: list[str] = []
    seen: set[str] = set()
    for raw in exceptions:
        token = raw.strip()
        if not token:
            continue
        if ":" not in token:
            raise ExceptionParseError(
                f"license exception {raw!r} must be in 'NAME:SPDX_ID' form "
                "(e.g. 'mongodb:AGPL-3.0-only')"
            )
        name_part, _, id_part = token.partition(":")
        name = name_part.strip().lower()
        id_raw = id_part.strip()
        if not name:
            raise ExceptionParseError(
                f"license exception {raw!r} has an empty component name "
                "(expected 'NAME:SPDX_ID')"
            )
        if not id_raw:
            raise ExceptionParseError(
                f"license exception {raw!r} has an empty SPDX id "
                "(expected 'NAME:SPDX_ID')"
            )
        canon_id = licenses._canonical_id(id_raw) or id_raw
        rendered = f"{name}:{canon_id}"
        if rendered in seen:
            continue
        seen.add(rendered)
        canonical.append(rendered)
        lookup.setdefault(name, set()).add(canon_id)
    return lookup, canonical


def check(
    sbom: "Sbom",
    disallow: list[str] | None = None,
    exceptions: list[str] | None = None,
) -> SbomLicenseReport:
    """Score an :class:`~embalmer.sbom.Sbom` against a license policy.

    ``disallow`` is the list of SPDX ids to fail on (typically passed via
    ``--disallow-license`` once per id). ``None`` / empty list runs the check
    in informational-only mode: every component's category is recorded but no
    component is marked disallowed (``compliant`` stays ``True``).

    ``exceptions`` is the list of per-component disallow waivers (typically
    passed via ``--license-exception`` once per rule, each rule in
    ``"<name>:<spdx-id>"`` form). A rule waives a single (component, license)
    pair: ``mongodb:AGPL-3.0-only`` allows ``AGPL-3.0-only`` specifically on
    a component named ``mongodb`` while still failing the disallow policy
    when any *other* component declares AGPL. Name matching is
    case-insensitive; the SPDX id is canonicalized for matching.

    An exception only has an effect when paired with a ``disallow`` policy
    (there is nothing to waive otherwise). An exception that names no
    component in the inventory, or names an id no component declares, is
    silently inert — the policy did not need to use it.

    Raises:
        ExceptionParseError: if any ``exceptions`` entry is malformed
            (missing ``:``, empty name, empty id).
    """
    canon_disallow = _canonicalize_disallow(disallow)
    disallow_set = set(canon_disallow)
    exception_lookup, canon_exceptions = _parse_exceptions(exceptions)

    components: list[ComponentLicense] = []
    counts: dict[str, int] = {cat: 0 for cat in ALL_CATEGORIES}
    for comp in sbom.components:
        declared = comp.license_id
        category = categorize(declared)
        ids = _extract_ids(declared) if declared else []
        matched = [i for i in ids if i in disallow_set]
        # Apply per-component exceptions. An id appears in `exempted` only
        # when both (a) the disallow policy matched it and (b) an exception
        # for this component's name covered that id. The component "name"
        # is matched case-insensitively (see _parse_exceptions docstring).
        exempt_for_comp = exception_lookup.get(comp.name.lower(), set())
        disallowed_here = [i for i in matched if i not in exempt_for_comp]
        exempted_here = [i for i in matched if i in exempt_for_comp]
        components.append(
            ComponentLicense(
                purl=comp.purl(),
                name=comp.name,
                version=comp.version,
                declared=declared,
                category=category,
                ids=ids,
                disallowed=disallowed_here,
                exempted=exempted_here,
            )
        )
        counts[category] = counts.get(category, 0) + 1

    compliant = all(c.allowed for c in components)
    return SbomLicenseReport(
        compliant=compliant,
        disallow=canon_disallow,
        exceptions=canon_exceptions,
        components=components,
        category_counts=counts,
    )
