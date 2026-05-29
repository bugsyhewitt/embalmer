"""SPDX license-expression validation.

The ``licenseDeclared`` field of an SPDX package and the ``license`` of a
CycloneDX component are not free text: the SPDX spec requires them to be a valid
**SPDX license expression** — a recognized SPDX license identifier (``MIT``,
``GPL-2.0-only``), a ``LicenseRef-`` reference to a document-local extracted
license, the ``NOASSERTION`` / ``NONE`` sentinels, or a compound expression
built from those with ``AND`` / ``OR`` / ``WITH`` operators and parentheses
(SPDX spec, Annex D).

Firmware package databases do not honor this. An apk ``L:`` field — the one
license string embalmer reads from the filesystem — routinely carries a
non-SPDX token: a bare ``GPL`` (no version, not an SPDX id), a distro-ism like
``custom`` or ``Public-Domain``, or vendor free text. Emitting those verbatim
into ``licenseDeclared`` produces a document that strict SPDX validators
(ntia-conformance-checker, the SPDX online validator, ORT) reject, which defeats
the whole point of speaking the standard format.

This module validates a declared license string against a curated set of the
SPDX identifiers that actually appear in Linux firmware, and tells the SBOM
renderers how to emit it spec-compliantly:

    - a **valid** expression is emitted verbatim (``licenseDeclared: "MIT"``);
    - an **invalid / non-SPDX** string is emitted as a document-local
      ``LicenseRef-<sanitized>`` with a matching ``hasExtractedLicensingInfos``
      entry recording the original text — exactly the escape hatch the SPDX spec
      provides for "a license that is not on the SPDX License List".

The result is an SBOM that is honest about what the firmware declared *and*
valid against the SPDX schema, instead of one that silently smuggles malformed
license tokens into a standards field.

The license set is curated, not the full ~700-entry SPDX List: embalmer is not a
license scanner, it inventories firmware, and the curated set covers the
licenses that real dpkg/opkg/apk databases declare. An identifier outside the
set is treated as non-SPDX and routed through the ``LicenseRef`` path — a
conservative, always-valid fallback, never a hard error.
"""

from __future__ import annotations

import re

# Curated SPDX license identifiers seen in Linux firmware package databases.
# Stored lowercased for case-insensitive *lookup*; the canonical (spec-cased)
# form is the value, because SPDX identifiers are case-sensitive on output even
# though many databases lowercase them.
_SPDX_LICENSES: dict[str, str] = {
    canon.lower(): canon
    for canon in (
        # permissive
        "MIT",
        "MIT-0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-4-Clause",
        "0BSD",
        "ISC",
        "Apache-2.0",
        "Apache-1.1",
        "Zlib",
        "libpng-2.0",
        "X11",
        "Unlicense",
        "WTFPL",
        "BSL-1.0",
        "Python-2.0",
        "PSF-2.0",
        "OpenSSL",
        "curl",
        "NCSA",
        "Beerware",
        # copyleft (GPL family, modern SPDX -only / -or-later forms)
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "MPL-1.1",
        "MPL-2.0",
        "EPL-1.0",
        "EPL-2.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "Artistic-1.0",
        "Artistic-2.0",
        # public-domain dedications
        "CC0-1.0",
        "CC-BY-3.0",
        "CC-BY-4.0",
        "CC-BY-SA-3.0",
        "CC-BY-SA-4.0",
        # the SPDX sentinels are valid expressions in their own right
        "NOASSERTION",
        "NONE",
    )
}

# SPDX "license exception" identifiers usable after the WITH operator.
_SPDX_EXCEPTIONS: dict[str, str] = {
    canon.lower(): canon
    for canon in (
        "Classpath-exception-2.0",
        "GCC-exception-2.0",
        "GCC-exception-3.1",
        "LLVM-exception",
        "Autoconf-exception-2.0",
        "Autoconf-exception-3.0",
        "Bison-exception-2.2",
        "Font-exception-2.0",
        "Linux-syscall-note",
        "OpenSSL-exception",
        "u-boot-exception-2.0",
    )
}

# A license identifier is letters/digits with ``.``/``-`` separators, optionally
# trailing ``+`` (the SPDX "or-later" shorthand, e.g. ``Apache-2.0+``). A
# ``LicenseRef-`` / ``DocumentRef-...:LicenseRef-`` reference is also a valid
# atom. Operators are the case-sensitive keywords AND / OR / WITH.
_SIMPLE_ID = re.compile(r"^[A-Za-z0-9.\-]+\+?$")
_LICENSE_REF = re.compile(r"^(DocumentRef-[A-Za-z0-9.\-]+:)?LicenseRef-[A-Za-z0-9.\-]+$")

# Characters allowed inside a sanitized LicenseRef idstring (SPDX: idstring is
# ``[a-zA-Z0-9.\-]+``). Everything else collapses to ``-``.
_LICENSEREF_DISALLOWED = re.compile(r"[^A-Za-z0-9.\-]+")


def _canonical_id(token: str) -> str | None:
    """Return the canonical SPDX id for ``token`` (case-insensitive), or None.

    Handles the ``+`` "or-later" shorthand: ``apache-2.0+`` matches the listed
    ``Apache-2.0`` and is returned with its ``+`` preserved in canonical case.
    """
    plus = token.endswith("+")
    bare = token[:-1] if plus else token
    canon = _SPDX_LICENSES.get(bare.lower())
    if canon is None:
        return None
    return canon + "+" if plus else canon


def _tokenize(expr: str) -> list[str]:
    """Split an SPDX expression into atoms, operators, and parentheses.

    Parentheses are emitted as their own tokens; whitespace separates the rest.
    """
    spaced = expr.replace("(", " ( ").replace(")", " ) ")
    return spaced.split()


def is_valid_expression(expr: str) -> bool:
    """True if ``expr`` is a syntactically valid SPDX license expression.

    Recognizes single ids, ``LicenseRef``/``DocumentRef`` references, the
    ``NOASSERTION``/``NONE`` sentinels, and compound expressions joined by
    ``AND``/``OR``/``WITH`` with balanced parentheses. License and exception
    identifiers are validated against the curated SPDX set; an unknown
    identifier makes the whole expression invalid (so the caller routes it
    through the ``LicenseRef`` extracted-license path).

    The grammar is the SPDX one (Annex D) restricted to what firmware declares:

        expr      := term (("AND"|"OR") term)*
        term      := atom ("WITH" exception)?
        atom      := id | licenseref | "(" expr ")"
    """
    tokens = _tokenize(expr)
    if not tokens:
        return False

    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def parse_expr() -> bool:
        nonlocal pos
        if not parse_term():
            return False
        while True:
            tok = peek()
            if tok in ("AND", "OR"):
                pos += 1
                if not parse_term():
                    return False
            else:
                break
        return True

    def parse_term() -> bool:
        nonlocal pos
        if not parse_atom():
            return False
        if peek() == "WITH":
            pos += 1
            exc = peek()
            if exc is None or _SPDX_EXCEPTIONS.get(exc.lower()) is None:
                return False
            pos += 1
        return True

    def parse_atom() -> bool:
        nonlocal pos
        tok = peek()
        if tok is None:
            return False
        if tok == "(":
            pos += 1
            if not parse_expr():
                return False
            if peek() != ")":
                return False
            pos += 1
            return True
        if tok in ("AND", "OR", "WITH", ")"):
            return False
        # A bare identifier or a LicenseRef/DocumentRef reference.
        if _LICENSE_REF.match(tok):
            pos += 1
            return True
        if _SIMPLE_ID.match(tok) and _canonical_id(tok) is not None:
            pos += 1
            return True
        return False

    if not parse_expr():
        return False
    return pos == len(tokens)


def canonicalize_expression(expr: str) -> str:
    """Return ``expr`` with each identifier replaced by its canonical SPDX case.

    Only meaningful for an expression that :func:`is_valid_expression` accepts;
    operators, parentheses, and ``LicenseRef`` atoms pass through unchanged. A
    database that declares ``mit`` or ``apache-2.0`` is emitted as the
    spec-cased ``MIT`` / ``Apache-2.0``.
    """
    out: list[str] = []
    for tok in _tokenize(expr):
        if tok in ("AND", "OR", "WITH", "(", ")"):
            out.append(tok)
        elif _LICENSE_REF.match(tok):
            out.append(tok)
        else:
            canon = _canonical_id(tok)
            if canon is not None:
                out.append(canon)
                continue
            exc = _SPDX_EXCEPTIONS.get(tok.lower())
            out.append(exc if exc is not None else tok)
    # Re-join, re-attaching parentheses to their neighbors without stray spaces.
    text = " ".join(out)
    text = text.replace("( ", "(").replace(" )", ")")
    return text


def license_ref_id(text: str) -> str:
    """Sanitize an arbitrary license string into a ``LicenseRef-`` identifier.

    SPDX ``LicenseRef`` idstrings are constrained to ``[A-Za-z0-9.-]``; any other
    character in the original token (a slash, space, plus, parenthesis, …) is
    replaced so the reference stays spec-valid while remaining recognizable. An
    empty result (a license string of only disallowed characters) falls back to
    a stable placeholder so the reference is always well-formed.
    """
    cleaned = _LICENSEREF_DISALLOWED.sub("-", text).strip("-")
    return f"LicenseRef-{cleaned or 'unknown'}"
