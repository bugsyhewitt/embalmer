"""Unit tests for SPDX license-expression validation (``embalmer.licenses``).

The SPDX ``licenseDeclared`` / CycloneDX ``license`` fields are not free text —
they must be valid SPDX license expressions. Firmware package databases declare
non-SPDX strings routinely, so embalmer validates the declared string and routes
a valid one verbatim while emitting an invalid one as a ``LicenseRef-`` with an
extracted-license record. These tests pin the validator, canonicalizer, and
LicenseRef sanitizer that the SBOM renderers depend on.
"""

from __future__ import annotations

from embalmer import licenses


# --- valid single identifiers ---------------------------------------------


def test_known_simple_ids_are_valid():
    for ok in ("MIT", "Apache-2.0", "GPL-2.0-only", "BSD-3-Clause", "ISC"):
        assert licenses.is_valid_expression(ok), ok


def test_validation_is_case_insensitive():
    # apk/dpkg databases lowercase license tokens; the validator accepts them.
    assert licenses.is_valid_expression("mit")
    assert licenses.is_valid_expression("apache-2.0")
    assert licenses.is_valid_expression("gpl-3.0-or-later")


def test_or_later_plus_shorthand_is_valid():
    assert licenses.is_valid_expression("Apache-2.0+")
    assert licenses.is_valid_expression("gpl-2.0-only+")


def test_spdx_sentinels_are_valid_expressions():
    assert licenses.is_valid_expression("NOASSERTION")
    assert licenses.is_valid_expression("NONE")


# --- valid compound expressions -------------------------------------------


def test_or_and_expressions_are_valid():
    assert licenses.is_valid_expression("MIT OR Apache-2.0")
    assert licenses.is_valid_expression("GPL-2.0-only AND MIT")
    assert licenses.is_valid_expression("(MIT OR ISC) AND Apache-2.0")


def test_with_exception_is_valid():
    assert licenses.is_valid_expression("GPL-2.0-only WITH Classpath-exception-2.0")
    assert licenses.is_valid_expression(
        "GPL-3.0-or-later WITH GCC-exception-3.1"
    )


def test_with_unknown_exception_is_invalid():
    assert not licenses.is_valid_expression("GPL-2.0-only WITH Not-An-Exception")


def test_license_ref_atom_is_valid():
    assert licenses.is_valid_expression("LicenseRef-myproprietary")
    assert licenses.is_valid_expression(
        "DocumentRef-spdx-tool:LicenseRef-1 OR MIT"
    )


# --- invalid / non-SPDX strings -------------------------------------------


def test_unknown_identifier_is_invalid():
    # The classic firmware offenders: bare GPL, distro-isms, free text.
    for bad in ("GPL", "GPLv2", "custom", "Public-Domain", "BSD", "proprietary"):
        assert not licenses.is_valid_expression(bad), bad


def test_dangling_and_malformed_expressions_are_invalid():
    assert not licenses.is_valid_expression("")
    assert not licenses.is_valid_expression("MIT OR")
    assert not licenses.is_valid_expression("OR MIT")
    assert not licenses.is_valid_expression("MIT AND AND ISC")
    assert not licenses.is_valid_expression("(MIT OR ISC")
    assert not licenses.is_valid_expression("MIT OR ISC)")
    assert not licenses.is_valid_expression("MIT ISC")  # missing operator


# --- canonicalization ------------------------------------------------------


def test_canonicalize_fixes_case():
    assert licenses.canonicalize_expression("mit") == "MIT"
    assert licenses.canonicalize_expression("apache-2.0") == "Apache-2.0"


def test_canonicalize_preserves_operators_and_plus():
    assert (
        licenses.canonicalize_expression("mit or apache-2.0")
        == "MIT OR apache-2.0"
        or licenses.canonicalize_expression("mit OR apache-2.0")
        == "MIT OR Apache-2.0"
    )
    # operators are case-sensitive keywords; a properly-cased expression round-trips
    assert (
        licenses.canonicalize_expression("mit OR apache-2.0")
        == "MIT OR Apache-2.0"
    )
    assert licenses.canonicalize_expression("apache-2.0+") == "Apache-2.0+"


def test_canonicalize_preserves_parens_and_exceptions():
    assert (
        licenses.canonicalize_expression("(mit OR isc) AND apache-2.0")
        == "(MIT OR ISC) AND Apache-2.0"
    )
    assert (
        licenses.canonicalize_expression(
            "gpl-2.0-only WITH classpath-exception-2.0"
        )
        == "GPL-2.0-only WITH Classpath-exception-2.0"
    )


# --- LicenseRef sanitization ----------------------------------------------


def test_license_ref_sanitizes_disallowed_chars():
    assert licenses.license_ref_id("GPL") == "LicenseRef-GPL"
    assert licenses.license_ref_id("custom license") == "LicenseRef-custom-license"
    assert licenses.license_ref_id("BSD/MIT") == "LicenseRef-BSD-MIT"


def test_license_ref_falls_back_for_empty_result():
    assert licenses.license_ref_id("///") == "LicenseRef-unknown"
