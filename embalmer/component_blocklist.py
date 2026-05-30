"""SBOM component-blocklist enforcement.

The SBOM lists every third-party component embalmer recovers from a firmware
image — package-database components (dpkg/opkg/apk) and binary-detected
libraries (BusyBox, OpenSSL, …). The CVE cross-reference (``--sbom-cve`` /
``--sbom-osv``) tells the consumer which components carry *known* CVEs, and the
license check (``--sbom-license-check``) tells them which components fail a
license policy. What neither tells them is the third compliance question:

    *"Is the firmware shipping a component my policy specifically forbids?"*

A real procurement / supply-chain policy bans specific components on grounds
that go beyond CVE coverage — EOL OpenSSL 1.0.x is forbidden because *the
upstream no longer ships security fixes*, even when no specific CVE is open;
Log4j 1.x is forbidden because *the project has been declared end-of-life*;
BusyBox older than 1.30 is forbidden because of accumulated unfixed defects
the project never backported. The CVE databases will not always carry these as
explicit matches, but the procurement policy still needs to fail the build.

This module is that policy gate. It is the procurement-side companion to the
license-policy gate shipped in Phase 2 Rotation 32
(:mod:`embalmer.sbom_license`):

  * ``--sbom-license-check`` gates on *what license a component carries*;
  * ``--component-blocklist`` gates on *which component is shipping*.

The blocklist is a list of patterns of the form ``NAME[@VERSION_SPEC]``,
passed once per pattern (repeatable). The supported version-spec grammar is
deliberately small — operators read it at a glance, the matcher has no edge
cases, and the most common procurement patterns ("all 1.0.x", "anything older
than 1.30") are first-class:

    ``openssl``              — any version of openssl
    ``openssl@1.0.1f``       — exactly that version
    ``openssl@1.0.*``        — any 1.0.x version (prefix wildcard)
    ``busybox@<1.30``        — anything older than 1.30 (also <=, >=, >)
    ``log4j@1.*``            — any 1.x version

Matching is **case-insensitive on the name** (SBOM component names are not
case-normalized — ``BusyBox`` vs. ``busybox`` should both block). A pattern
with no ``@`` matches every version of the named component (the "this
component is banned outright" case). A version spec is matched against the
component's declared version string verbatim — embalmer does not perform
semver normalization, so the spec language is the literal-prefix /
literal-compare grammar above, not full semver.

The verdict rides under a new ``sbom.component_blocklist`` report key as a
structured pass/fail conformance report — overall ``compliant`` boolean, the
canonicalized ``blocklist`` policy, the per-component verdicts (every SBOM
component is recorded with ``blocked: true/false`` for uniform downstream
consumption), and the list of patterns that matched each blocked component
(useful for the operator to see *why* a component tripped — a name-only
pattern is more permissive than a version-pinned one).

Self-contained: no network call, no new dependency, reads the in-memory
:class:`~embalmer.sbom.Sbom`. Off by default — every existing report path is
byte-for-byte unchanged. Composes with ``--fail-on`` (R31) the same way
``sbom.vulnerabilities`` does: each blocked component is scored at the
``high`` severity tier and counted by the gate, so

    ``--component-blocklist openssl@1.0.* --fail-on high``

fails the build with exit code 10 when the firmware ships any OpenSSL 1.0.x
component, without the operator having to parse the JSON verdict themselves.

Honest posture preserved: the policy matches what the SBOM *declared* —
embalmer does not guess whether a non-listed component might secretly contain
a blocked one (a statically-linked library not detected by the ``components``
check is invisible to this gate just as it is invisible to the rest of the
SBOM machinery), and the verdict carries the name/version verbatim so the
operator can audit a false match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .sbom import Component, Sbom


#: Severity assigned to each blocked component for the ``--fail-on`` gate.
#: ``high`` is the right tier: a blocked component is a procurement-policy
#: violation, the same severity class the existing severity ladder assigns to
#: a known-exploited CVE — both are "fail the build" events in CI.
BLOCKED_SEVERITY = "high"


# --- version-spec grammar --------------------------------------------------


# The comparison operators supported by a version spec. Order matters: the
# two-char operators must be tried before their single-char prefixes so a
# spec of ``<=1.0`` is not parsed as the ``<`` operator with literal value
# ``=1.0``.
_OPERATORS: tuple[str, ...] = ("<=", ">=", "<", ">")


def _parse_pattern(raw: str) -> tuple[str, str | None] | None:
    """Parse a ``NAME[@VERSION_SPEC]`` blocklist pattern.

    Returns ``(name_lower, version_spec_or_None)`` for a valid pattern, or
    ``None`` for an unusable one (empty, name-only with empty name, etc.).
    The name is lowercased here so per-component matching can do a single
    lookup; the version spec is returned verbatim (operator and value, if
    any) so the matcher can dispatch on its first character.
    """
    if not raw:
        return None
    token = raw.strip()
    if not token:
        return None
    if "@" in token:
        name, _, version = token.partition("@")
        name = name.strip()
        version = version.strip()
        if not name:
            return None
        # An empty version after @ degrades to "any version" — same as a
        # name-only pattern, but tolerated so a user passing ``--component-blocklist openssl@``
        # gets a sensible match rather than a silent skip.
        return (name.lower(), version if version else None)
    return (token.lower(), None)


def _version_matches(declared: str, spec: str) -> bool:
    """Whether a declared version string matches a version spec.

    Supported spec forms:

      * ``1.0.1f``  — exact (string-equal) match
      * ``1.0.*``   — prefix wildcard (the spec without the trailing ``*``
        must be a prefix of the declared version)
      * ``<X`` / ``<=X`` / ``>=X`` / ``>X`` — lexicographic compare on the
        operand. We deliberately do **not** parse semver: a procurement
        policy's "anything older than 1.30" is a literal-prefix check on
        package version strings, which are not all semver (e.g. dpkg's
        ``5.0-4ubuntu1``). Lexicographic compare is good enough for the
        wildcard / prefix-bound patterns the procurement use-case wants;
        an operator who needs full semver writes an exact pin or a
        wildcard.

    An unparseable spec (operator with empty operand, etc.) does not match —
    the matcher is *fail-safe*: a malformed pattern blocks nothing rather
    than blocking everything by accident.
    """
    if not spec:
        # An empty / missing spec means "any version" — the caller decides
        # whether to even consult the version, so we return True for safety.
        return True

    # Operator forms come first because their leading character is unique to
    # the operator-prefixed grammar (``<``/``>``).
    for op in _OPERATORS:
        if spec.startswith(op):
            operand = spec[len(op):].strip()
            if not operand:
                return False
            if op == "<":
                return declared < operand
            if op == "<=":
                return declared <= operand
            if op == ">":
                return declared > operand
            if op == ">=":
                return declared >= operand

    # Prefix wildcard: ``1.0.*`` matches ``1.0.1f``, ``1.0.2``, etc. The
    # leading ``*`` (suffix wildcard ``*.0``) is *not* supported — package
    # versions are read left-to-right and procurement policies pin from the
    # left ("ban every 1.0.x"), not the right. A pattern starting with ``*``
    # is treated as a literal, which will fail to match any real version
    # (the fail-safe stance).
    if spec.endswith("*"):
        prefix = spec[:-1]
        return declared.startswith(prefix)

    # No operator, no wildcard: exact match.
    return declared == spec


def _component_matches(
    component: "Component", patterns: list[tuple[str, str | None]]
) -> list[str]:
    """Return the list of patterns (rendered as their original ``NAME[@SPEC]``
    form) that match this component.

    A component can match more than one pattern — e.g. both ``openssl`` (the
    name-only pattern) and ``openssl@1.0.*`` (the version-pinned one) match an
    OpenSSL 1.0.1f component. The report records all matches so the operator
    can see which policy lines are doing the blocking.
    """
    matched: list[str] = []
    comp_name_lower = component.name.lower()
    for name, spec in patterns:
        if comp_name_lower != name:
            continue
        if spec is None:
            matched.append(name)
            continue
        if _version_matches(component.version, spec):
            matched.append(f"{name}@{spec}")
    return matched


# --- per-component result and overall report -------------------------------


@dataclass
class BlockedComponent:
    """A component verdict against the blocklist policy."""

    #: Component identity for the verdict (the same purl the SBOM emits).
    purl: str
    name: str
    version: str
    #: The blocklist patterns this component matched. Empty when the
    #: component is allowed; one or more entries when blocked (each rendered
    #: as ``NAME`` or ``NAME@SPEC`` exactly as the operator wrote it,
    #: name-lowercased).
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        """Whether this component is blocked by the policy."""
        return bool(self.matched_patterns)

    @property
    def severity(self) -> str | None:
        """The severity tier the ``--fail-on`` gate counts this verdict at.

        Blocked components are scored at :data:`BLOCKED_SEVERITY`; allowed
        components carry no severity (they do not appear in the gate's
        tally). Returned as ``None`` for allowed components so the report
        consumer can dispatch on presence.
        """
        return BLOCKED_SEVERITY if self.blocked else None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "purl": self.purl,
            "name": self.name,
            "version": self.version,
            "blocked": self.blocked,
        }
        if self.blocked:
            out["matched_patterns"] = list(self.matched_patterns)
            out["severity"] = BLOCKED_SEVERITY
        return out


@dataclass
class ComponentBlocklistReport:
    """The blocklist compliance report for an SBOM."""

    #: Overall verdict: ``True`` when no component matched the blocklist.
    #: A report with no blocklist always reports ``compliant=True``
    #: (informational-only mode — every component is recorded but none is
    #: blocked).
    compliant: bool
    #: Blocklist policy (canonicalized patterns) the report was scored
    #: against. Each entry is the operator's literal pattern with the name
    #: lowercased (e.g. ``"openssl@1.0.*"``).
    blocklist: list[str] = field(default_factory=list)
    #: Per-component verdicts, in the SBOM's component order.
    components: list[BlockedComponent] = field(default_factory=list)

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def blocked_components(self) -> list[BlockedComponent]:
        """Per-component verdicts that matched the blocklist policy."""
        return [c for c in self.components if c.blocked]

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": "Component-blocklist compliance",
            "compliant": self.compliant,
            "blocklist": list(self.blocklist),
            "component_count": self.component_count,
            "blocked_component_count": len(self.blocked_components),
            "components": [c.to_dict() for c in self.components],
        }


# --- public entry points ---------------------------------------------------


def _canonicalize_blocklist(
    raw_patterns: list[str] | None,
) -> tuple[list[tuple[str, str | None]], list[str]]:
    """Parse and canonicalize a user-supplied blocklist.

    Returns ``(parsed_patterns, rendered_patterns)``:

      * ``parsed_patterns`` is the list of ``(name_lower, spec_or_None)``
        tuples the matcher consumes;
      * ``rendered_patterns`` is the same list rendered back into
        ``NAME`` / ``NAME@SPEC`` form for the report (name lowercased, spec
        verbatim) — the same string a per-component ``matched_patterns``
        entry uses, so the two views agree.

    Empty / unparseable patterns are silently skipped (the fail-safe stance).
    """
    if not raw_patterns:
        return [], []
    parsed: list[tuple[str, str | None]] = []
    rendered: list[str] = []
    for raw in raw_patterns:
        result = _parse_pattern(raw)
        if result is None:
            continue
        name, spec = result
        parsed.append((name, spec))
        rendered.append(name if spec is None else f"{name}@{spec}")
    return parsed, rendered


def check(
    sbom: "Sbom", blocklist: list[str] | None = None
) -> ComponentBlocklistReport:
    """Score an :class:`~embalmer.sbom.Sbom` against a component blocklist.

    ``blocklist`` is the list of ``NAME[@VERSION_SPEC]`` patterns to block
    (typically one per ``--component-blocklist`` CLI invocation). ``None``
    / empty runs the check in informational-only mode: every component is
    recorded with ``blocked=False`` and the overall verdict is
    ``compliant=True``.
    """
    parsed, rendered = _canonicalize_blocklist(blocklist)

    components: list[BlockedComponent] = []
    for comp in sbom.components:
        matched = _component_matches(comp, parsed) if parsed else []
        components.append(
            BlockedComponent(
                purl=comp.purl(),
                name=comp.name,
                version=comp.version,
                matched_patterns=matched,
            )
        )

    compliant = all(not c.blocked for c in components)
    return ComponentBlocklistReport(
        compliant=compliant,
        blocklist=rendered,
        components=components,
    )
