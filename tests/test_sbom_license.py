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
