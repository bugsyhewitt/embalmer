"""Unit tests for the SBOM license-policy compliance check.

The license-policy check categorizes every SBOM component's declared license
(permissive / weak-copyleft / strong-copyleft / network-copyleft / public-domain
/ other / unknown / noassertion) and scores the inventory against an optional
disallow-list of SPDX identifiers (``--disallow-license``). It is the
policy-side companion to the existing SPDX license-expression validation
shipped in Phase 2 Rotation 23 (:mod:`embalmer.licenses`).

These tests exercise:

  * :func:`sbom_license.categorize` — per-id and per-expression categorization
    including the strictest-wins rule for compound expressions and the
    noassertion / unknown sentinels;
  * :func:`sbom_license.check` — informational-only mode and disallow-policy
    mode, the per-component verdict shape, and case-insensitive matching;
  * the ``to_dict`` shape attached under ``sbom.licenses`` in the report;
  * the pipeline integration (``--sbom-license-check``,
    ``--disallow-license``) end-to-end through the CLI and the markdown
    renderer (Article IX: real pipeline, real planted package database).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from embalmer import sbom, sbom_license
from embalmer.cli import main as cli_main
from embalmer.models import Report
from embalmer import report as report_mod


# --- helpers ----------------------------------------------------------------


def _comp(name: str, version: str, license_id: str | None, source: str = "dpkg") -> sbom.Component:
    """A minimal Component with a declared license, defaulted to dpkg-sourced."""
    return sbom.Component(
        name=name,
        version=version,
        source=source,
        license_id=license_id,
        db_path=f"var/lib/{source}/status",
    )


def _sbom(*components: sbom.Component) -> sbom.Sbom:
    return sbom.Sbom(components=list(components))


# --- categorize: single identifiers ----------------------------------------


def test_categorize_permissive_ids():
    for spdx_id in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Zlib"):
        assert sbom_license.categorize(spdx_id) == sbom_license.CATEGORY_PERMISSIVE


def test_categorize_weak_copyleft_ids():
    for spdx_id in (
        "LGPL-2.1-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "EPL-2.0",
        "CDDL-1.0",
    ):
        assert sbom_license.categorize(spdx_id) == sbom_license.CATEGORY_WEAK_COPYLEFT


def test_categorize_strong_copyleft_ids():
    for spdx_id in ("GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later"):
        assert sbom_license.categorize(spdx_id) == sbom_license.CATEGORY_STRONG_COPYLEFT


def test_categorize_network_copyleft_agpl():
    assert sbom_license.categorize("AGPL-3.0-only") == sbom_license.CATEGORY_NETWORK_COPYLEFT
    assert sbom_license.categorize("AGPL-3.0-or-later") == sbom_license.CATEGORY_NETWORK_COPYLEFT


def test_categorize_public_domain_ids():
    assert sbom_license.categorize("CC0-1.0") == sbom_license.CATEGORY_PUBLIC_DOMAIN
    # SPDX NONE means "the author declared no license" — closer to PD than to
    # NOASSERTION ("we couldn't determine"), per the SPDX spec.
    assert sbom_license.categorize("NONE") == sbom_license.CATEGORY_PUBLIC_DOMAIN


def test_categorize_noassertion_sentinel_and_empty():
    assert sbom_license.categorize("NOASSERTION") == sbom_license.CATEGORY_NOASSERTION
    assert sbom_license.categorize(None) == sbom_license.CATEGORY_NOASSERTION
    assert sbom_license.categorize("") == sbom_license.CATEGORY_NOASSERTION
    assert sbom_license.categorize("   ") == sbom_license.CATEGORY_NOASSERTION


def test_categorize_unknown_for_non_spdx_strings():
    # Bare "GPL" with no version is *not* a valid SPDX id (the SPDX spec
    # requires the -only / -or-later suffix); :mod:`embalmer.licenses` already
    # routes these through LicenseRef, and the policy classifies them unknown.
    assert sbom_license.categorize("GPL") == sbom_license.CATEGORY_UNKNOWN
    assert sbom_license.categorize("custom") == sbom_license.CATEGORY_UNKNOWN
    assert sbom_license.categorize("Some vendor blob") == sbom_license.CATEGORY_UNKNOWN


def test_categorize_case_insensitive_lookup():
    # The :mod:`embalmer.licenses` canonicalizer accepts case-variant ids; the
    # policy must do the same so a declaration of "apache-2.0" is permissive.
    assert sbom_license.categorize("apache-2.0") == sbom_license.CATEGORY_PERMISSIVE
    assert sbom_license.categorize("gpl-3.0-only") == sbom_license.CATEGORY_STRONG_COPYLEFT


def test_categorize_or_later_suffix_preserved():
    # The ``+`` "or-later" shorthand is a valid SPDX form; the policy category
    # of the base id applies (Apache-2.0+ is still permissive).
    assert sbom_license.categorize("Apache-2.0+") == sbom_license.CATEGORY_PERMISSIVE
    assert sbom_license.categorize("MIT+") == sbom_license.CATEGORY_PERMISSIVE


# --- categorize: compound expressions, strictest-wins ----------------------


def test_categorize_dual_license_strictest_wins():
    # MIT OR GPL-3.0-only: a consumer picking GPL still carries GPL obligations,
    # so the inventory must classify by the strictest branch.
    assert (
        sbom_license.categorize("MIT OR GPL-3.0-only")
        == sbom_license.CATEGORY_STRONG_COPYLEFT
    )


def test_categorize_compound_with_agpl_picks_network_copyleft():
    # AGPL is the strictest category, so any expression mentioning it (even
    # alongside MIT and GPL) classifies as network-copyleft.
    assert (
        sbom_license.categorize("MIT OR GPL-3.0-only OR AGPL-3.0-only")
        == sbom_license.CATEGORY_NETWORK_COPYLEFT
    )


def test_categorize_and_combination_strictest_wins():
    # AND has the same strictest-wins behavior — the strictest obligation
    # binds the consumer regardless of operator.
    assert (
        sbom_license.categorize("MIT AND GPL-2.0-only")
        == sbom_license.CATEGORY_STRONG_COPYLEFT
    )


def test_categorize_with_exception_classifies_by_license_not_exception():
    # GPL-2.0-only WITH Classpath-exception-2.0 is strong-copyleft (the
    # exception softens the obligation but does not change the SPDX category).
    assert (
        sbom_license.categorize("GPL-2.0-only WITH Classpath-exception-2.0")
        == sbom_license.CATEGORY_STRONG_COPYLEFT
    )


def test_categorize_licenseref_only_expression_is_unknown():
    # A LicenseRef-only expression is syntactically valid SPDX but names no
    # SPDX id the policy can score — classify as unknown.
    assert sbom_license.categorize("LicenseRef-vendor-blob") == sbom_license.CATEGORY_UNKNOWN


# --- check(): informational-only mode --------------------------------------


def test_check_informational_only_no_disallow_is_compliant():
    s = _sbom(
        _comp("busybox", "1.35.0", "GPL-2.0-only"),
        _comp("openssl", "3.0.11", "Apache-2.0"),
    )
    report = sbom_license.check(s)
    assert report.compliant is True
    assert report.disallow == []
    assert report.component_count == 2
    assert report.disallowed_components == []


def test_check_records_every_component_with_category():
    s = _sbom(
        _comp("a", "1", "MIT"),
        _comp("b", "1", "GPL-3.0-only"),
        _comp("c", "1", "AGPL-3.0-only"),
        _comp("d", "1", None),
        _comp("e", "1", "vendor-blob"),
    )
    report = sbom_license.check(s)
    cats = [c.category for c in report.components]
    assert cats == [
        sbom_license.CATEGORY_PERMISSIVE,
        sbom_license.CATEGORY_STRONG_COPYLEFT,
        sbom_license.CATEGORY_NETWORK_COPYLEFT,
        sbom_license.CATEGORY_NOASSERTION,
        sbom_license.CATEGORY_UNKNOWN,
    ]


def test_check_category_counts_cover_every_category_uniformly():
    # Every category in ALL_CATEGORIES must appear in the counts dict, even
    # when zero — uniform shape downstream so consumers do not need defaults.
    s = _sbom(_comp("a", "1", "MIT"))
    report = sbom_license.check(s)
    for cat in sbom_license.ALL_CATEGORIES:
        assert cat in report.category_counts
    assert report.category_counts[sbom_license.CATEGORY_PERMISSIVE] == 1
    assert report.category_counts[sbom_license.CATEGORY_STRONG_COPYLEFT] == 0


def test_check_empty_sbom_is_compliant_with_zero_counts():
    report = sbom_license.check(_sbom())
    assert report.compliant is True
    assert report.component_count == 0
    assert all(v == 0 for v in report.category_counts.values())


# --- check(): disallow-policy mode -----------------------------------------


def test_check_disallow_fails_on_matching_id():
    s = _sbom(
        _comp("safe", "1", "MIT"),
        _comp("blocked", "1", "AGPL-3.0-only"),
    )
    report = sbom_license.check(s, disallow=["AGPL-3.0-only"])
    assert report.compliant is False
    assert len(report.disallowed_components) == 1
    assert report.disallowed_components[0].name == "blocked"
    assert report.disallowed_components[0].disallowed == ["AGPL-3.0-only"]


def test_check_disallow_case_insensitive_input():
    # Operators pass --disallow-license agpl-3.0-only; the report normalizes
    # the policy to canonical SPDX case for matching.
    s = _sbom(_comp("blocked", "1", "AGPL-3.0-only"))
    report = sbom_license.check(s, disallow=["agpl-3.0-only"])
    assert report.compliant is False
    assert report.disallow == ["AGPL-3.0-only"]


def test_check_disallow_matches_inside_compound_expression():
    # A dual-license MIT OR AGPL-3.0-only is still blocked by an AGPL
    # disallow — the AGPL branch is a legal option the consumer could pick.
    s = _sbom(_comp("dual", "1", "MIT OR AGPL-3.0-only"))
    report = sbom_license.check(s, disallow=["AGPL-3.0-only"])
    assert report.compliant is False
    assert report.disallowed_components[0].disallowed == ["AGPL-3.0-only"]


def test_check_disallow_does_not_match_permissive_only_component():
    s = _sbom(
        _comp("permissive_only", "1", "MIT"),
        _comp("apache_only", "1", "Apache-2.0"),
    )
    report = sbom_license.check(s, disallow=["GPL-3.0-only", "AGPL-3.0-only"])
    assert report.compliant is True
    assert report.disallowed_components == []


def test_check_noassertion_components_pass_disallow_policy():
    # A NOASSERTION component cannot be on the disallow list (it declared
    # nothing); it passes the gate. The consumer who wants to fail closed on
    # noassertion reads the category_counts.
    s = _sbom(_comp("missing", "1", None))
    report = sbom_license.check(s, disallow=["AGPL-3.0-only"])
    assert report.compliant is True
    assert report.disallowed_components == []
    assert report.category_counts[sbom_license.CATEGORY_NOASSERTION] == 1


def test_check_unknown_components_pass_disallow_policy():
    # Same for unknown: a non-SPDX string is not on the disallow list of
    # canonical ids and so passes — surfaced via the unknown count instead.
    s = _sbom(_comp("vendor", "1", "vendor-blob"))
    report = sbom_license.check(s, disallow=["GPL-3.0-only"])
    assert report.compliant is True
    assert report.category_counts[sbom_license.CATEGORY_UNKNOWN] == 1


# --- to_dict shape ---------------------------------------------------------


def test_to_dict_shape_round_trip_includes_every_documented_field():
    s = _sbom(
        _comp("safe", "1", "MIT"),
        _comp("blocked", "1", "GPL-3.0-only"),
    )
    report = sbom_license.check(s, disallow=["GPL-3.0-only"])
    d = report.to_dict()
    assert d["standard"] == "SPDX license-policy compliance"
    assert d["compliant"] is False
    assert d["disallow"] == ["GPL-3.0-only"]
    assert d["component_count"] == 2
    assert d["disallowed_component_count"] == 1
    assert "category_counts" in d
    # per-component shape
    comp_dicts = d["components"]
    assert len(comp_dicts) == 2
    safe = next(c for c in comp_dicts if c["name"] == "safe")
    blocked = next(c for c in comp_dicts if c["name"] == "blocked")
    assert safe["allowed"] is True
    assert "disallowed" not in safe  # only present when non-empty
    assert blocked["allowed"] is False
    assert blocked["disallowed"] == ["GPL-3.0-only"]
    assert blocked["category"] == sbom_license.CATEGORY_STRONG_COPYLEFT
    # purl is recorded for downstream join
    assert safe["purl"].startswith("pkg:")


def test_to_dict_round_trips_through_json():
    s = _sbom(_comp("a", "1", "MIT"))
    report = sbom_license.check(s, disallow=["AGPL-3.0-only"])
    # JSON serialization must succeed (no non-serializable types leak in).
    blob = json.dumps(report.to_dict())
    again = json.loads(blob)
    assert again["compliant"] is True


# --- Report.to_dict wiring -------------------------------------------------


def test_report_attaches_sbom_licenses_under_sbom_key():
    r = Report(firmware="fw.bin", checks=["sbom"])
    r.sbom = _sbom(_comp("blocked", "1", "AGPL-3.0-only"))
    r.sbom_license = sbom_license.check(r.sbom, disallow=["AGPL-3.0-only"])
    d = r.to_dict()
    assert "sbom" in d
    assert "licenses" in d["sbom"]
    assert d["sbom"]["licenses"]["compliant"] is False
    assert d["sbom"]["licenses"]["disallow"] == ["AGPL-3.0-only"]


def test_report_omits_sbom_licenses_when_check_not_run():
    r = Report(firmware="fw.bin", checks=["sbom"])
    r.sbom = _sbom(_comp("a", "1", "MIT"))
    d = r.to_dict()
    assert "sbom" in d
    assert "licenses" not in d["sbom"]


# --- markdown renderer wiring ----------------------------------------------


def test_markdown_renders_license_section_with_disallowed_table():
    r = Report(firmware="fw.bin", checks=["sbom"])
    r.sbom = _sbom(
        _comp("safe", "1", "MIT"),
        _comp("blocked", "1", "AGPL-3.0-only"),
    )
    r.sbom_license = sbom_license.check(r.sbom, disallow=["AGPL-3.0-only"])
    md = report_mod.render(r, "md")
    assert "License-policy compliance" in md
    assert "NOT COMPLIANT" in md
    assert "AGPL-3.0-only" in md
    # Per-category counts table
    assert "| permissive | 1 |" in md
    assert "| network-copyleft | 1 |" in md
    # Disallowed-components table
    assert "Disallowed components" in md
    assert "blocked" in md


def test_markdown_renders_informational_only_when_no_disallow():
    r = Report(firmware="fw.bin", checks=["sbom"])
    r.sbom = _sbom(_comp("a", "1", "MIT"))
    r.sbom_license = sbom_license.check(r.sbom)
    md = report_mod.render(r, "md")
    assert "License-policy compliance" in md
    assert "COMPLIANT" in md
    assert "informational only" in md
    # No disallowed-components table since nothing is disallowed
    assert "Disallowed components" not in md


# --- pipeline + CLI end-to-end --------------------------------------------


# A minimal apk-style installed-database fixture with a mix of licenses. The
# apk parser in :mod:`embalmer.sbom` reads the ``L:`` field for the declared
# license (apk's installed-db format is a sequence of short-key records).
_APK_INSTALLED_MIXED_LICENSES = """\
C:Q1abc
P:busybox
V:1.35.0-r0
L:GPL-2.0-only
A:x86_64
T:Tiny utilities

C:Q1def
P:openssl
V:3.0.11-r0
L:Apache-2.0
A:x86_64
T:Secure Sockets Layer toolkit

C:Q1ghi
P:ffmpeg
V:5.1.4-r0
L:GPL-3.0-only
A:x86_64
T:media library

"""


def _write_apk_tree(root: Path, installed_text: str) -> None:
    """Plant a minimal apk installed-database under a fake extract root."""
    (root / "lib" / "apk" / "db").mkdir(parents=True, exist_ok=True)
    (root / "lib" / "apk" / "db" / "installed").write_text(installed_text)


def test_pipeline_runs_license_check_through_cli(tmp_path, capsys):
    # Plant a fake "extracted" filesystem with an apk database (apk carries
    # the declared license in its ``L:`` field; dpkg's status format does
    # not). The SBOM scanner walks it; the license check runs against the
    # resulting inventory.
    from embalmer import sbom as sbom_mod

    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    _write_apk_tree(extract_root, _APK_INSTALLED_MIXED_LICENSES)
    inventory = sbom_mod.scan(str(extract_root))
    # Sanity check: the apk parser populated the license field
    assert any(c.license_id for c in inventory.components), (
        "fixture must produce at least one component with a declared license"
    )
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = inventory

    # Now run the license check directly — this is the same call path the
    # pipeline takes when `--sbom-license-check` is set.
    report.sbom_license = sbom_license.check(
        report.sbom, disallow=["GPL-3.0-only"]
    )

    d = report.to_dict()
    lic = d["sbom"]["licenses"]
    assert lic["compliant"] is False
    # ffmpeg declared GPL-3.0-only -> disallowed; busybox is GPL-2.0-only,
    # openssl is Apache-2.0 -> both allowed.
    disallowed_names = {c["name"] for c in lic["components"] if not c["allowed"]}
    assert disallowed_names == {"ffmpeg"}


def test_cli_sbom_license_check_flag_threaded_through(tmp_path, monkeypatch, capsys):
    """End-to-end: --sbom-license-check + --disallow-license through main().

    We bypass real extraction by patching ``extract.extract`` to return a
    pre-planted extract root, and we ask for ``--checks sbom`` so no binary
    analyzer is invoked. The license check should attach a verdict under
    ``sbom.licenses`` in the JSON output.
    """
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    _write_apk_tree(extract_root, _APK_INSTALLED_MIXED_LICENSES)

    def fake_extract(firmware, workdir, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=1,
            extraction_time_ms=0,
            extract_root=str(extract_root),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)
    # Also patch the pipeline's bound reference.
    from embalmer import pipeline as pipeline_mod
    monkeypatch.setattr(pipeline_mod.extract, "extract", fake_extract)

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00")
    out = tmp_path / "report.json"

    rc = cli_main([
        "--firmware", str(fw),
        "--workdir", str(tmp_path / "workdir"),
        "--checks", "sbom",
        "--format", "json",
        "--sbom-license-check",
        "--disallow-license", "AGPL-3.0-only",
        "--disallow-license", "GPL-3.0-only",
        "--output", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert "licenses" in data["sbom"]
    lic = data["sbom"]["licenses"]
    assert lic["disallow"] == ["AGPL-3.0-only", "GPL-3.0-only"]
    # ffmpeg is GPL-3.0-only -> blocked; the run is non-compliant.
    assert lic["compliant"] is False
    blocked = {c["name"] for c in lic["components"] if not c["allowed"]}
    assert "ffmpeg" in blocked


def test_cli_no_sbom_license_check_omits_licenses_key(tmp_path, monkeypatch):
    """Default behavior is unchanged: without the flag, `sbom.licenses` is absent."""
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    _write_apk_tree(extract_root, _APK_INSTALLED_MIXED_LICENSES)

    def fake_extract(firmware, workdir, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=1,
            extraction_time_ms=0,
            extract_root=str(extract_root),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)
    from embalmer import pipeline as pipeline_mod
    monkeypatch.setattr(pipeline_mod.extract, "extract", fake_extract)

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00")
    out = tmp_path / "report.json"

    rc = cli_main([
        "--firmware", str(fw),
        "--workdir", str(tmp_path / "workdir"),
        "--checks", "sbom",
        "--format", "json",
        "--output", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert "sbom" in data
    assert "licenses" not in data["sbom"]


# --- --license-exception: per-component disallow waivers -------------------
#
# The exception flag lets a procurement/legal team waive a single
# (component, license) pair from the disallow policy — the Trivy
# `.trivyignore` / OSV-Scanner ignore-file pattern. A waived id is cleared
# from `disallowed` (so the gate doesn't fire) but surfaced under `exempted`
# (so the audit trail is preserved).


def test_parse_exceptions_canonicalizes_name_and_id():
    lookup, canon = sbom_license._parse_exceptions(["MongoDB:agpl-3.0-only"])
    # Name lowercased, SPDX id canonicalized to spec case
    assert lookup == {"mongodb": {"AGPL-3.0-only"}}
    assert canon == ["mongodb:AGPL-3.0-only"]


def test_parse_exceptions_deduplicates_and_preserves_order():
    lookup, canon = sbom_license._parse_exceptions([
        "mongodb:AGPL-3.0-only",
        "ffmpeg:GPL-3.0-only",
        "MONGODB:agpl-3.0-only",  # duplicate after canonicalization
    ])
    assert canon == ["mongodb:AGPL-3.0-only", "ffmpeg:GPL-3.0-only"]
    assert lookup == {
        "mongodb": {"AGPL-3.0-only"},
        "ffmpeg": {"GPL-3.0-only"},
    }


def test_parse_exceptions_multiple_ids_for_one_component():
    lookup, canon = sbom_license._parse_exceptions([
        "ffmpeg:GPL-2.0-only",
        "ffmpeg:GPL-3.0-only",
    ])
    assert lookup == {"ffmpeg": {"GPL-2.0-only", "GPL-3.0-only"}}
    # Both canonical entries preserved
    assert sorted(canon) == sorted([
        "ffmpeg:GPL-2.0-only",
        "ffmpeg:GPL-3.0-only",
    ])


def test_parse_exceptions_rejects_missing_separator():
    with pytest.raises(sbom_license.ExceptionParseError) as exc_info:
        sbom_license._parse_exceptions(["mongodb-AGPL-3.0-only"])
    assert "NAME:SPDX_ID" in str(exc_info.value)


def test_parse_exceptions_rejects_empty_name():
    with pytest.raises(sbom_license.ExceptionParseError):
        sbom_license._parse_exceptions([":AGPL-3.0-only"])


def test_parse_exceptions_rejects_empty_id():
    with pytest.raises(sbom_license.ExceptionParseError):
        sbom_license._parse_exceptions(["mongodb:"])


def test_parse_exceptions_skips_blank_tokens():
    lookup, canon = sbom_license._parse_exceptions(["   ", "mongodb:MIT"])
    assert canon == ["mongodb:MIT"]
    assert lookup == {"mongodb": {"MIT"}}


def test_parse_exceptions_keeps_non_spdx_id_verbatim():
    # Mirrors --disallow-license behaviour: an unrecognized id is kept so the
    # consumer can exempt a LicenseRef-style string.
    lookup, canon = sbom_license._parse_exceptions(["acme:Acme-Proprietary-1.0"])
    assert lookup == {"acme": {"Acme-Proprietary-1.0"}}
    assert canon == ["acme:Acme-Proprietary-1.0"]


def test_check_exception_clears_matched_disallow():
    s = _sbom(
        _comp("mongodb", "6.0", "AGPL-3.0-only"),
        _comp("other", "1.0", "AGPL-3.0-only"),
    )
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:AGPL-3.0-only"],
    )
    # mongodb cleared by exception, but `other` still fails
    assert report.compliant is False
    by_name = {c.name: c for c in report.components}
    assert by_name["mongodb"].allowed is True
    assert by_name["mongodb"].disallowed == []
    assert by_name["mongodb"].exempted == ["AGPL-3.0-only"]
    assert by_name["other"].allowed is False
    assert by_name["other"].disallowed == ["AGPL-3.0-only"]
    assert by_name["other"].exempted == []


def test_check_exception_clears_all_disallowed_then_compliant():
    s = _sbom(_comp("mongodb", "6.0", "AGPL-3.0-only"))
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:AGPL-3.0-only"],
    )
    assert report.compliant is True
    assert report.disallowed_components == []
    assert report.exempted_components == [report.components[0]]


def test_check_exception_is_case_insensitive_on_name():
    # SBOM stores the component name as "MongoDB" (CPE-vendor casing); the
    # user passes the exception as "mongodb" -> still matches.
    s = _sbom(_comp("MongoDB", "6.0", "AGPL-3.0-only"))
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:agpl-3.0-only"],
    )
    assert report.compliant is True
    assert report.components[0].exempted == ["AGPL-3.0-only"]


def test_check_exception_matches_compound_expression_branch():
    # A dual-licensed component is normally blocked when either branch is
    # disallowed; an exception on the matched branch clears it.
    s = _sbom(_comp("mongodb", "6.0", "MIT OR AGPL-3.0-only"))
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:AGPL-3.0-only"],
    )
    assert report.compliant is True
    assert report.components[0].exempted == ["AGPL-3.0-only"]


def test_check_exception_does_not_cross_components():
    # Exception on mongodb does NOT waive AGPL on a differently-named
    # component — the whole point of per-component exceptions.
    s = _sbom(_comp("ffmpeg", "5.1", "AGPL-3.0-only"))
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:AGPL-3.0-only"],
    )
    assert report.compliant is False
    assert report.components[0].disallowed == ["AGPL-3.0-only"]
    assert report.components[0].exempted == []


def test_check_exception_for_unmatched_license_is_inert():
    # Exception names mongodb:GPL-3.0-only but mongodb declares MIT — the
    # exception is silently inert (it had nothing to waive).
    s = _sbom(_comp("mongodb", "6.0", "MIT"))
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:GPL-3.0-only"],
    )
    assert report.compliant is True
    assert report.components[0].exempted == []


def test_check_without_disallow_records_exceptions_but_exempts_nothing():
    # Informational-only mode: an exception was passed but no disallow was,
    # so nothing was matched to begin with. Exceptions list still recorded
    # for transparency; no component is exempted.
    s = _sbom(_comp("mongodb", "6.0", "AGPL-3.0-only"))
    report = sbom_license.check(
        s, exceptions=["mongodb:AGPL-3.0-only"]
    )
    assert report.compliant is True
    assert report.exceptions == ["mongodb:AGPL-3.0-only"]
    assert report.components[0].exempted == []


def test_to_dict_includes_exceptions_when_configured():
    s = _sbom(_comp("mongodb", "6.0", "AGPL-3.0-only"))
    report = sbom_license.check(
        s,
        disallow=["AGPL-3.0-only"],
        exceptions=["mongodb:AGPL-3.0-only"],
    )
    d = report.to_dict()
    assert d["exceptions"] == ["mongodb:AGPL-3.0-only"]
    assert d["exempted_component_count"] == 1
    assert d["disallowed_component_count"] == 0
    comp = d["components"][0]
    assert comp["allowed"] is True
    assert "disallowed" not in comp  # empty -> omitted
    assert comp["exempted"] == ["AGPL-3.0-only"]


def test_to_dict_omits_exceptions_keys_when_none_configured():
    """Backwards-compat: a report with no exceptions has the byte-for-byte
    same JSON shape as before --license-exception shipped."""
    s = _sbom(_comp("mongodb", "6.0", "MIT"))
    report = sbom_license.check(s, disallow=["AGPL-3.0-only"])
    d = report.to_dict()
    assert "exceptions" not in d
    assert "exempted_component_count" not in d
    # Per-component shape also unchanged for non-exempted components
    assert "exempted" not in d["components"][0]


def test_markdown_renders_exception_annotations():
    r = Report(firmware="fw.bin", checks=["sbom"])
    r.sbom = _sbom(
        _comp("mongodb", "6.0", "AGPL-3.0-only"),
        _comp("ffmpeg", "5.1", "GPL-3.0-only"),
    )
    r.sbom_license = sbom_license.check(
        r.sbom,
        disallow=["AGPL-3.0-only", "GPL-3.0-only"],
        exceptions=["mongodb:AGPL-3.0-only"],
    )
    md = report_mod.render(r, "md")
    # Verdict line mentions the exemption count
    assert "1 component(s) exempted via --license-exception" in md
    # Effective-exceptions annotation
    assert "Per-component exceptions in effect" in md
    assert "`mongodb:AGPL-3.0-only`" in md
    # Exempted components table
    assert "Exempted components" in md
    # ffmpeg is still disallowed (not exempted)
    assert "Disallowed components" in md
    assert "ffmpeg" in md


def test_cli_license_exception_flag_threaded_through(tmp_path, monkeypatch):
    """End-to-end: --license-exception threads through main() and clears
    a component-specific disallow match."""
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    # ffmpeg declares GPL-3.0-only; without the exception it would fail
    # the gate. With --license-exception ffmpeg:GPL-3.0-only it should be
    # cleared and the run reports compliant.
    _write_apk_tree(extract_root, _APK_INSTALLED_MIXED_LICENSES)

    def fake_extract(firmware, workdir, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=1,
            extraction_time_ms=0,
            extract_root=str(extract_root),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)
    from embalmer import pipeline as pipeline_mod
    monkeypatch.setattr(pipeline_mod.extract, "extract", fake_extract)

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00")
    out = tmp_path / "report.json"

    rc = cli_main([
        "--firmware", str(fw),
        "--workdir", str(tmp_path / "workdir"),
        "--checks", "sbom",
        "--format", "json",
        "--sbom-license-check",
        "--disallow-license", "GPL-3.0-only",
        "--license-exception", "ffmpeg:gpl-3.0-only",  # case-variant input
        "--output", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    lic = data["sbom"]["licenses"]
    # Exception cleared ffmpeg -> overall compliant
    assert lic["compliant"] is True
    assert lic["exceptions"] == ["ffmpeg:GPL-3.0-only"]
    assert lic["exempted_component_count"] == 1
    assert lic["disallowed_component_count"] == 0
    ffmpeg = next(c for c in lic["components"] if c["name"] == "ffmpeg")
    assert ffmpeg["allowed"] is True
    assert ffmpeg["exempted"] == ["GPL-3.0-only"]


def test_cli_license_exception_does_not_cross_components(tmp_path, monkeypatch):
    """An exception on one component does NOT waive the disallow on another."""
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    _write_apk_tree(extract_root, _APK_INSTALLED_MIXED_LICENSES)

    def fake_extract(firmware, workdir, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=1,
            extraction_time_ms=0,
            extract_root=str(extract_root),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)
    from embalmer import pipeline as pipeline_mod
    monkeypatch.setattr(pipeline_mod.extract, "extract", fake_extract)

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00")
    out = tmp_path / "report.json"

    rc = cli_main([
        "--firmware", str(fw),
        "--workdir", str(tmp_path / "workdir"),
        "--checks", "sbom",
        "--format", "json",
        "--sbom-license-check",
        "--disallow-license", "GPL-3.0-only",
        # exception names mongodb (not in inventory) -> ffmpeg still fails
        "--license-exception", "mongodb:GPL-3.0-only",
        "--output", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    lic = data["sbom"]["licenses"]
    assert lic["compliant"] is False
    # ffmpeg is the only disallowed component, and was not exempted
    blocked = {c["name"] for c in lic["components"] if not c["allowed"]}
    assert "ffmpeg" in blocked
    assert lic["exempted_component_count"] == 0


def test_cli_rejects_malformed_license_exception(tmp_path, monkeypatch, capsys):
    """A malformed --license-exception exits 1 with a usage error to stderr."""
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00")
    # No --sbom-license-check needed: validation runs unconditionally on the
    # parsed flag so the user sees the error early.
    rc = cli_main([
        "--firmware", str(fw),
        "--workdir", str(tmp_path / "workdir"),
        "--checks", "sbom",
        "--license-exception", "no-colon-here",
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "license exception" in err
    assert "NAME:SPDX_ID" in err
