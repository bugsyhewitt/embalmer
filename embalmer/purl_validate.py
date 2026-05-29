"""CycloneDX component purl (Package URL) validation.

embalmer *generates* a CycloneDX 1.6 BOM from its package inventory
(:meth:`embalmer.sbom.Sbom.to_cyclonedx`). The single most important field on
each ``component`` is its **purl** (Package URL) — it is the
CycloneDX-recommended component identifier and the key downstream tools
(Dependency-Track, Grype, OSV-Scanner, OWASP dep-scan) join on to match a
component against vulnerability databases. A component whose purl is malformed
is silently un-matchable: the BOM looks complete, but every vuln scanner that
ingests it drops that component on the floor.

The NTIA check (:mod:`embalmer.ntia`) scores the BOM's *content* against the
federal minimum data fields and the SPDX validator
(:mod:`embalmer.spdx_validate`) proves the SPDX relationship graph is
well-formed; this module is the CycloneDX-side companion: it validates that
every component's purl conforms to the **package-url specification**
(https://github.com/package-url/purl-spec), the syntax CycloneDX 1.6 requires
for the ``component.purl`` field.

A purl has the canonical shape::

    pkg:type/namespace/name@version?qualifiers#subpath

embalmer emits the ``pkg:type/name@version`` core (plus an ``?arch=`` qualifier
when a package declares an architecture), so this validator focuses on the parts
embalmer produces and the invariants the spec makes mandatory:

    1. scheme        — the purl begins with the literal ``pkg:`` scheme.
    2. type          — a non-empty, lowercase ``type`` component made of the
       spec's allowed type characters (``[a-z0-9.+-]``, no leading digit), and
       drawn from the set of types embalmer assigns (deb/opkg/apk/generic).
    3. name          — a non-empty ``name`` component (the spec requires it; a
       purl with no name identifies nothing).
    4. version       — a non-empty ``version`` after the ``@`` separator (the
       spec makes version optional, but an SBOM component with no version is
       useless for vuln matching, so embalmer requires it and the check flags
       its absence).
    5. encoding      — every component segment is correctly percent-encoded per
       the spec (the special characters that must be encoded — a space, ``/``,
       ``?``, ``#`` inside a segment — actually are), so the purl round-trips.
    6. qualifiers    — the ``?key=value`` qualifier string is well-formed: each
       key is a non-empty lowercase ``[a-z0-9.-_]`` token, values are present,
       and no key repeats.

Because embalmer constructs every purl with :func:`urllib.parse.quote` and a
fixed type map, a real generated BOM passes all six checks — the validation is a
*guarantee* on the generator's output (the same posture as the SPDX validator)
and gives a consumer a structured pass/fail to gate their pipeline on. It adds
no dependency and makes no network call: purl validity is a property of the
string, and this surfaces it explicitly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, unquote

if TYPE_CHECKING:
    from .sbom import Sbom

# The purl scheme is the literal ``pkg`` (package-url spec, "scheme is constant").
SCHEME = "pkg"

# A purl ``type`` is "composed only of ASCII letters and numbers, '.', '+' and
# '-' (period, plus, and dash)", "MUST start with an ASCII letter", and "MUST be
# lowercased" (package-url spec, "type"). embalmer only ever emits the four types
# in :data:`KNOWN_TYPES`, but the regex enforces the full spec rule so an
# externally-supplied purl is judged by the standard, not just embalmer's subset.
_TYPE_RE = re.compile(r"^[a-z][a-z0-9.+-]*$")

# The purl types embalmer assigns (mirrors the map in ``Component.purl``). A type
# outside this set is still spec-valid syntactically but flagged as one embalmer
# did not produce — a signal the BOM was tampered with or merged from elsewhere.
KNOWN_TYPES: frozenset[str] = frozenset({"deb", "opkg", "apk", "generic"})

# A qualifier key is "composed only of ASCII letters and numbers, '.', '-' and
# '_'", "MUST be lowercased", and "MUST NOT be percent-encoded" (spec,
# "qualifiers"). Values may be percent-encoded; only the key syntax is fixed.
_QUALIFIER_KEY_RE = re.compile(r"^[a-z0-9.\-_]+$")

# Canonical check identifiers, in the report's stable order.
SCHEME_PREFIX = "scheme_prefix"
TYPE_VALID = "type_valid"
NAME_PRESENT = "name_present"
VERSION_PRESENT = "version_present"
ENCODING_VALID = "encoding_valid"
QUALIFIERS_VALID = "qualifiers_valid"

#: All checks, in canonical report order.
ALL_CHECKS: tuple[str, ...] = (
    SCHEME_PREFIX,
    TYPE_VALID,
    NAME_PRESENT,
    VERSION_PRESENT,
    ENCODING_VALID,
    QUALIFIERS_VALID,
)

#: Human-readable label for each check.
CHECK_LABELS: dict[str, str] = {
    SCHEME_PREFIX: "purl scheme prefix",
    TYPE_VALID: "purl type valid",
    NAME_PRESENT: "purl name present",
    VERSION_PRESENT: "purl version present",
    ENCODING_VALID: "purl segments correctly encoded",
    QUALIFIERS_VALID: "purl qualifiers well-formed",
}


@dataclass
class CheckResult:
    """The result of one purl check across all components."""

    check: str
    label: str
    #: ``True`` when every component's purl satisfies this invariant.
    passed: bool
    #: The purls (or "purl: reason" strings) that violated the check (empty when
    #: it passed). Kept so a consumer can pinpoint *which* component is broken.
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
class PurlValidationReport:
    """The purl-validation report for a CycloneDX BOM's components."""

    valid: bool
    checks: list[CheckResult] = field(default_factory=list)
    component_count: int = 0

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failures(self) -> list[str]:
        """The labels of the checks that failed (report order)."""
        return [c.label for c in self.checks if not c.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "package-url (purl) component validation",
            "valid": self.valid,
            "component_count": self.component_count,
            "checks_total": len(self.checks),
            "checks_passed": self.passed_count,
            "failed_checks": self.failures,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class _ParsedPurl:
    """A purl decomposed into the parts the checks reason over.

    ``valid_scheme`` records whether the ``pkg:`` prefix was present; when it is
    not, the remaining parsed fields are best-effort and the scheme check is the
    one that fails. Everything else is the raw (still percent-encoded) segment so
    the encoding check can inspect it.
    """

    raw: str
    valid_scheme: bool
    type: str = ""
    name: str = ""
    version: str = ""
    qualifier_str: str = ""


def _parse(purl: str) -> _ParsedPurl:
    """Decompose a purl into scheme/type/name/version/qualifiers.

    Splits on the spec's separators only — it does *not* judge validity, it just
    locates the segments so each check can apply its own rule. The subpath
    (``#...``) is stripped (embalmer never emits one) so it cannot leak into the
    qualifier or version segment.
    """
    rest = purl
    valid_scheme = rest.startswith(SCHEME + ":")
    if valid_scheme:
        rest = rest[len(SCHEME) + 1 :]
    # Strip a leading "//" — the spec allows (and tools tolerate) ``pkg://``.
    rest = rest.lstrip("/")

    # Subpath first (everything after the first '#'), discarded.
    rest = rest.split("#", 1)[0]

    # Qualifiers (everything after the first '?').
    qualifier_str = ""
    if "?" in rest:
        rest, qualifier_str = rest.split("?", 1)

    # type is up to the first '/'.
    ptype = ""
    if "/" in rest:
        ptype, rest = rest.split("/", 1)
    else:
        # No '/', so the whole thing is the type (a malformed purl with no
        # name); leave name empty so NAME_PRESENT flags it.
        ptype, rest = rest, ""

    # name@version: the name is the last path segment, version after its '@'.
    # embalmer never emits a namespace, but tolerate one by taking the final
    # segment as name-bearing.
    name_seg = rest.rsplit("/", 1)[-1]
    version = ""
    name = name_seg
    if "@" in name_seg:
        name, version = name_seg.split("@", 1)

    return _ParsedPurl(
        raw=purl,
        valid_scheme=valid_scheme,
        type=ptype,
        name=name,
        version=version,
        qualifier_str=qualifier_str,
    )


def _is_canonically_encoded(segment: str) -> bool:
    """True if ``segment`` is a correctly percent-encoded purl path component.

    A purl segment must percent-encode the characters that are otherwise
    structural (a space, ``/``, ``?``, ``#``) so the purl round-trips. The test:
    decode the segment, re-encode it with the same rule embalmer uses
    (:func:`urllib.parse.quote` with ``safe=''``), and require the input to
    already equal that canonical encoding. A raw space or unescaped ``/`` inside
    a name fails because its canonical form differs.
    """
    decoded = unquote(segment)
    return quote(decoded, safe="") == segment


def _check_scheme(parsed: list[_ParsedPurl]) -> CheckResult:
    bad = [p.raw for p in parsed if not p.valid_scheme]
    ok = not bad
    detail = (
        f"all {len(parsed)} purl(s) begin with the '{SCHEME}:' scheme"
        if ok
        else f"{len(bad)} purl(s) missing the '{SCHEME}:' scheme: "
        + ", ".join(repr(b) for b in bad)
    )
    return CheckResult(
        check=SCHEME_PREFIX,
        label=CHECK_LABELS[SCHEME_PREFIX],
        passed=ok,
        offenders=bad,
        detail=detail,
    )


def _check_type(parsed: list[_ParsedPurl]) -> CheckResult:
    bad: list[str] = []
    for p in parsed:
        if not _TYPE_RE.match(p.type):
            bad.append(f"{p.raw} (type {p.type!r} not spec-valid)")
        elif p.type not in KNOWN_TYPES:
            bad.append(f"{p.raw} (type {p.type!r} not one embalmer emits)")
    ok = not bad
    detail = (
        f"all {len(parsed)} purl type(s) are valid and embalmer-emitted"
        if ok
        else f"{len(bad)} purl(s) with an invalid/unknown type: "
        + "; ".join(bad)
    )
    return CheckResult(
        check=TYPE_VALID,
        label=CHECK_LABELS[TYPE_VALID],
        passed=ok,
        offenders=bad,
        detail=detail,
    )


def _check_name(parsed: list[_ParsedPurl]) -> CheckResult:
    # The name segment is still percent-encoded; decode before judging emptiness
    # so an all-encoded name ("%20") is not mistaken for empty.
    bad = [p.raw for p in parsed if not unquote(p.name).strip()]
    ok = not bad
    detail = (
        f"all {len(parsed)} purl(s) carry a non-empty name"
        if ok
        else f"{len(bad)} purl(s) with no name component: "
        + ", ".join(repr(b) for b in bad)
    )
    return CheckResult(
        check=NAME_PRESENT,
        label=CHECK_LABELS[NAME_PRESENT],
        passed=ok,
        offenders=bad,
        detail=detail,
    )


def _check_version(parsed: list[_ParsedPurl]) -> CheckResult:
    bad = [p.raw for p in parsed if not unquote(p.version).strip()]
    ok = not bad
    detail = (
        f"all {len(parsed)} purl(s) carry a non-empty version"
        if ok
        else f"{len(bad)} purl(s) with no version (needed for vuln matching): "
        + ", ".join(repr(b) for b in bad)
    )
    return CheckResult(
        check=VERSION_PRESENT,
        label=CHECK_LABELS[VERSION_PRESENT],
        passed=ok,
        offenders=bad,
        detail=detail,
    )


def _check_encoding(parsed: list[_ParsedPurl]) -> CheckResult:
    bad: list[str] = []
    for p in parsed:
        for label, seg in (("name", p.name), ("version", p.version)):
            if seg and not _is_canonically_encoded(seg):
                bad.append(f"{p.raw} ({label} segment not canonically encoded)")
    ok = not bad
    detail = (
        f"all {len(parsed)} purl(s) have correctly percent-encoded segments"
        if ok
        else f"{len(bad)} purl segment(s) not canonically encoded: "
        + "; ".join(bad)
    )
    return CheckResult(
        check=ENCODING_VALID,
        label=CHECK_LABELS[ENCODING_VALID],
        passed=ok,
        offenders=bad,
        detail=detail,
    )


def _check_qualifiers(parsed: list[_ParsedPurl]) -> CheckResult:
    bad: list[str] = []
    for p in parsed:
        if not p.qualifier_str:
            continue
        seen: set[str] = set()
        for pair in p.qualifier_str.split("&"):
            if not pair:
                continue
            if "=" not in pair:
                bad.append(f"{p.raw} (qualifier {pair!r} has no '=' value)")
                continue
            key, value = pair.split("=", 1)
            if not _QUALIFIER_KEY_RE.match(key):
                bad.append(f"{p.raw} (qualifier key {key!r} not lowercase token)")
            elif key in seen:
                bad.append(f"{p.raw} (qualifier key {key!r} repeats)")
            elif not value:
                bad.append(f"{p.raw} (qualifier {key!r} has an empty value)")
            seen.add(key)
    ok = not bad
    detail = (
        f"all {len(parsed)} purl(s) have well-formed qualifiers"
        if ok
        else f"{len(bad)} malformed qualifier(s): " + "; ".join(bad)
    )
    return CheckResult(
        check=QUALIFIERS_VALID,
        label=CHECK_LABELS[QUALIFIERS_VALID],
        passed=ok,
        offenders=bad,
        detail=detail,
    )


def validate_purls(purls: list[str]) -> PurlValidationReport:
    """Validate a list of purl strings against the package-url specification.

    Each check is applied across *all* purls and reports the offenders that
    violated it. ``valid`` is ``True`` only when every purl satisfies every
    invariant. An empty list is vacuously valid (no component, nothing to
    misidentify).
    """
    parsed = [_parse(pu) for pu in purls]
    results: list[CheckResult] = [
        _check_scheme(parsed),
        _check_type(parsed),
        _check_name(parsed),
        _check_version(parsed),
        _check_encoding(parsed),
        _check_qualifiers(parsed),
    ]
    valid = all(r.passed for r in results)
    return PurlValidationReport(
        valid=valid,
        checks=results,
        component_count=len(purls),
    )


def validate_document(bom: dict[str, Any]) -> PurlValidationReport:
    """Validate every ``component.purl`` in a rendered CycloneDX BOM document.

    ``bom`` is the ``dict`` produced by :meth:`embalmer.sbom.Sbom.to_cyclonedx`
    (or any CycloneDX 1.6 JSON BOM of the same shape). A component without a
    ``purl`` key contributes an empty string, which the scheme/name/version
    checks then flag — a component with no purl identifies nothing.
    """
    purls = [comp.get("purl", "") for comp in bom.get("components", [])]
    return validate_purls(purls)


def validate(sbom: "Sbom", firmware: str) -> PurlValidationReport:
    """Render ``sbom`` to a CycloneDX BOM and validate its component purls.

    Convenience wrapper for the pipeline: builds the CycloneDX document from the
    in-memory inventory (the same document the report emits under ``sbom.bom``)
    and validates every component's purl. ``firmware`` names the BOM subject,
    matching :meth:`embalmer.sbom.Sbom.to_cyclonedx`. A real embalmer-generated
    BOM passes all six checks — the validation is a *guarantee* on the
    generator's output, and a failure means the BOM carries a component a vuln
    scanner would silently fail to match.
    """
    return validate_document(sbom.to_cyclonedx(firmware))
