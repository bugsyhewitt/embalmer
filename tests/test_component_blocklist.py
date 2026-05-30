"""Unit tests for the SBOM component-blocklist compliance check.

The blocklist check scores every SBOM component against an operator-supplied
list of ``NAME[@VERSION_SPEC]`` patterns and attaches a structured pass/fail
verdict under ``sbom.component_blocklist``. It is the procurement-side
companion to ``--sbom-license-check`` shipped in Phase 2 Rotation 32: that
flag gates on *what license a component carries*, this one gates on *which
component is shipping at all* (the "EOL OpenSSL 1.0.x / Log4j 1.x /
BusyBox <1.30 is forbidden" case the CVE databases don't always carry).

These tests exercise:

  * pattern parsing (``NAME``, ``NAME@VERSION``, wildcard, compare operators);
  * per-component matching (case-insensitive name, version-spec dispatch);
  * the per-component / overall report shape and the ``to_dict`` round-trip;
  * the pipeline integration (``--component-blocklist``) end-to-end through
    the CLI and the markdown renderer;
  * the ``--fail-on`` gate composition: a blocklist match counts as a `high`
    severity finding and trips the gate at exit code 10.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from embalmer import component_blocklist, sbom
from embalmer.cli import main as cli_main
from embalmer.gate import GATE_EXIT_CODE, evaluate as evaluate_gate
from embalmer.models import Report
from embalmer import report as report_mod


# --- helpers ----------------------------------------------------------------


def _comp(
    name: str, version: str, source: str = "dpkg", architecture: str | None = None
) -> sbom.Component:
    """A minimal Component, defaulted to dpkg-sourced."""
    return sbom.Component(
        name=name,
        version=version,
        source=source,
        architecture=architecture,
        db_path=f"var/lib/{source}/status",
    )


def _sbom(*components: sbom.Component) -> sbom.Sbom:
    return sbom.Sbom(components=list(components))


# --- pattern parsing -------------------------------------------------------


def test_parse_pattern_name_only():
    assert component_blocklist._parse_pattern("openssl") == ("openssl", None)


def test_parse_pattern_name_with_version():
    assert component_blocklist._parse_pattern("openssl@1.0.1f") == (
        "openssl",
        "1.0.1f",
    )


def test_parse_pattern_lowercases_name():
    # SBOM component names are not case-normalized — the parser must lowercase
    # the name so a pattern of `OpenSSL` matches a component of `openssl`.
    assert component_blocklist._parse_pattern("OpenSSL@1.0.*") == (
        "openssl",
        "1.0.*",
    )


def test_parse_pattern_with_compare_operator_preserves_spec_verbatim():
    # The matcher dispatches on the spec's leading character, so the parser
    # returns the spec verbatim (operator + operand).
    assert component_blocklist._parse_pattern("busybox@<1.30") == (
        "busybox",
        "<1.30",
    )
    assert component_blocklist._parse_pattern("busybox@>=1.30") == (
        "busybox",
        ">=1.30",
    )


def test_parse_pattern_empty_inputs_return_none():
    assert component_blocklist._parse_pattern("") is None
    assert component_blocklist._parse_pattern("   ") is None
    assert component_blocklist._parse_pattern("@1.0") is None


def test_parse_pattern_trailing_at_degrades_to_name_only():
    # A user typing `--component-blocklist openssl@` (forgot the version) gets
    # a sensible "any version" match rather than a silent skip.
    assert component_blocklist._parse_pattern("openssl@") == ("openssl", None)


# --- version-spec matching --------------------------------------------------


def test_version_matches_exact():
    assert component_blocklist._version_matches("1.0.1f", "1.0.1f") is True
    assert component_blocklist._version_matches("1.0.1g", "1.0.1f") is False


def test_version_matches_prefix_wildcard():
    assert component_blocklist._version_matches("1.0.1f", "1.0.*") is True
    assert component_blocklist._version_matches("1.0.2", "1.0.*") is True
    assert component_blocklist._version_matches("1.1.0", "1.0.*") is False
    # The empty prefix `*` matches everything (a defensible degenerate
    # case for a `--component-blocklist openssl@*` written by a confused
    # operator — equivalent to the name-only ban).
    assert component_blocklist._version_matches("1.0.1f", "*") is True


def test_version_matches_less_than_operator():
    assert component_blocklist._version_matches("1.20", "<1.30") is True
    assert component_blocklist._version_matches("1.30", "<1.30") is False
    assert component_blocklist._version_matches("1.40", "<1.30") is False


def test_version_matches_less_than_or_equal_operator():
    assert component_blocklist._version_matches("1.20", "<=1.30") is True
    assert component_blocklist._version_matches("1.30", "<=1.30") is True
    assert component_blocklist._version_matches("1.40", "<=1.30") is False


def test_version_matches_greater_than_operator():
    assert component_blocklist._version_matches("2.0", ">1.30") is True
    assert component_blocklist._version_matches("1.30", ">1.30") is False
    assert component_blocklist._version_matches("1.20", ">1.30") is False


def test_version_matches_greater_than_or_equal_operator():
    assert component_blocklist._version_matches("2.0", ">=1.30") is True
    assert component_blocklist._version_matches("1.30", ">=1.30") is True
    assert component_blocklist._version_matches("1.20", ">=1.30") is False


def test_version_matches_two_char_operator_not_confused_with_one_char():
    # The matcher must try `<=` before `<` so a spec of `<=1.0` is not parsed
    # as the `<` operator with literal operand `=1.0`.
    assert component_blocklist._version_matches("1.0", "<=1.0") is True
    # The single-char compare would have rejected this (`"1.0" < "=1.0"`).


def test_version_matches_operator_with_empty_operand_does_not_match():
    # Fail-safe: a malformed `--component-blocklist openssl@<` blocks nothing
    # rather than blocking everything by accident.
    assert component_blocklist._version_matches("1.0", "<") is False
    assert component_blocklist._version_matches("1.0", ">=") is False


def test_version_matches_empty_spec_matches_anything():
    # An empty spec (passed when the matcher is invoked on a name-only
    # pattern) means "any version" and matches everything.
    assert component_blocklist._version_matches("1.0", "") is True


# --- per-component matching -------------------------------------------------


def test_component_matches_name_only_pattern():
    comp = _comp("openssl", "1.0.1f")
    matches = component_blocklist._component_matches(comp, [("openssl", None)])
    assert matches == ["openssl"]


def test_component_matches_case_insensitive_name():
    # The SBOM may carry `BusyBox` (binary detection often preserves
    # upstream casing); the pattern must still match.
    comp = _comp("BusyBox", "1.20.0")
    matches = component_blocklist._component_matches(comp, [("busybox", None)])
    assert matches == ["busybox"]


def test_component_matches_version_pinned_pattern():
    comp = _comp("openssl", "1.0.1f")
    matches = component_blocklist._component_matches(
        comp, [("openssl", "1.0.*")]
    )
    assert matches == ["openssl@1.0.*"]


def test_component_matches_both_name_only_and_version_pinned():
    # A component can match multiple patterns — the report records all of
    # them so an operator can see which policy lines did the blocking.
    comp = _comp("openssl", "1.0.1f")
    matches = component_blocklist._component_matches(
        comp, [("openssl", None), ("openssl", "1.0.*")]
    )
    assert matches == ["openssl", "openssl@1.0.*"]


def test_component_matches_name_mismatch_returns_empty():
    comp = _comp("curl", "7.50.0")
    matches = component_blocklist._component_matches(comp, [("openssl", None)])
    assert matches == []


def test_component_matches_name_hit_but_version_miss_returns_empty():
    comp = _comp("openssl", "3.0.11")
    matches = component_blocklist._component_matches(
        comp, [("openssl", "1.0.*")]
    )
    assert matches == []


# --- check(): informational-only mode --------------------------------------


def test_check_informational_only_no_blocklist_is_compliant():
    s = _sbom(_comp("busybox", "1.35.0"), _comp("openssl", "3.0.11"))
    report = component_blocklist.check(s)
    assert report.compliant is True
    assert report.blocklist == []
    assert report.component_count == 2
    assert report.blocked_components == []
    # Every component recorded with blocked=False.
    for comp in report.components:
        assert comp.blocked is False
        assert comp.matched_patterns == []


def test_check_empty_sbom_is_compliant():
    report = component_blocklist.check(_sbom())
    assert report.compliant is True
    assert report.component_count == 0
    assert report.blocked_components == []


# --- check(): blocklist mode -----------------------------------------------


def test_check_blocklist_blocks_exact_version_pin():
    s = _sbom(
        _comp("safe", "1.0"),
        _comp("openssl", "1.0.1f"),
    )
    report = component_blocklist.check(s, blocklist=["openssl@1.0.1f"])
    assert report.compliant is False
    assert len(report.blocked_components) == 1
    blocked = report.blocked_components[0]
    assert blocked.name == "openssl"
    assert blocked.version == "1.0.1f"
    assert blocked.matched_patterns == ["openssl@1.0.1f"]


def test_check_blocklist_blocks_wildcard_range():
    s = _sbom(
        _comp("openssl", "1.0.1f"),
        _comp("openssl", "3.0.11"),
    )
    report = component_blocklist.check(s, blocklist=["openssl@1.0.*"])
    assert report.compliant is False
    blocked = report.blocked_components
    assert len(blocked) == 1
    assert blocked[0].version == "1.0.1f"


def test_check_blocklist_blocks_name_only_pattern():
    # The operator wants to ban every version of log4j outright (the EOL
    # 1.x case where any version is suspect by procurement policy).
    s = _sbom(
        _comp("safe", "1.0"),
        _comp("log4j", "1.2.17"),
        _comp("log4j", "2.0.0"),
    )
    report = component_blocklist.check(s, blocklist=["log4j"])
    assert report.compliant is False
    assert len(report.blocked_components) == 2
    assert all(b.name == "log4j" for b in report.blocked_components)


def test_check_blocklist_blocks_less_than_compare():
    # "Anything older than busybox 1.30" — the recurring procurement pattern
    # for accumulated unfixed defects in an old release line.
    s = _sbom(
        _comp("busybox", "1.20.0"),
        _comp("busybox", "1.35.0"),
    )
    report = component_blocklist.check(s, blocklist=["busybox@<1.30"])
    assert report.compliant is False
    blocked = report.blocked_components
    assert len(blocked) == 1
    assert blocked[0].version == "1.20.0"


def test_check_blocklist_case_insensitive_name():
    # Operators write the pattern in any case; the matcher normalizes.
    s = _sbom(_comp("BusyBox", "1.20.0"))
    report = component_blocklist.check(s, blocklist=["busybox"])
    assert report.compliant is False
    assert report.blocked_components[0].name == "BusyBox"


def test_check_blocklist_records_every_component_uniformly():
    # Per-component verdicts in SBOM order; allowed components have an
    # empty matched_patterns list.
    s = _sbom(_comp("safe", "1.0"), _comp("openssl", "1.0.1f"))
    report = component_blocklist.check(s, blocklist=["openssl"])
    assert len(report.components) == 2
    assert report.components[0].blocked is False
    assert report.components[0].matched_patterns == []
    assert report.components[1].blocked is True


def test_check_blocklist_empty_or_unparseable_patterns_skipped():
    # Fail-safe: a blank pattern in the list is silently dropped rather
    # than treated as "block everything".
    s = _sbom(_comp("safe", "1.0"))
    report = component_blocklist.check(s, blocklist=["", "   ", "@1.0"])
    assert report.compliant is True
    assert report.blocklist == []
    assert report.blocked_components == []


def test_check_blocklist_multiple_patterns_match_independent_components():
    s = _sbom(
        _comp("openssl", "1.0.1f"),
        _comp("log4j", "1.2.17"),
        _comp("safe", "1.0"),
    )
    report = component_blocklist.check(s, blocklist=["openssl@1.0.*", "log4j"])
    assert report.compliant is False
    blocked_names = sorted(b.name for b in report.blocked_components)
    assert blocked_names == ["log4j", "openssl"]


# --- to_dict shape ---------------------------------------------------------


def test_to_dict_shape_round_trip_includes_every_documented_field():
    s = _sbom(_comp("safe", "1.0"), _comp("openssl", "1.0.1f"))
    report = component_blocklist.check(s, blocklist=["openssl@1.0.*"])
    d = report.to_dict()
    assert d["standard"] == "Component-blocklist compliance"
    assert d["compliant"] is False
    assert d["blocklist"] == ["openssl@1.0.*"]
    assert d["component_count"] == 2
    assert d["blocked_component_count"] == 1
    comp_dicts = d["components"]
    assert len(comp_dicts) == 2
    safe = next(c for c in comp_dicts if c["name"] == "safe")
    blocked = next(c for c in comp_dicts if c["name"] == "openssl")
    # Allowed components carry no `matched_patterns` / `severity` keys —
    # uniform shape would inflate the JSON for the common case.
    assert safe["blocked"] is False
    assert "matched_patterns" not in safe
    assert "severity" not in safe
    # Blocked components carry both, scored at the gate-friendly tier.
    assert blocked["blocked"] is True
    assert blocked["matched_patterns"] == ["openssl@1.0.*"]
    assert blocked["severity"] == component_blocklist.BLOCKED_SEVERITY == "high"


def test_to_dict_purl_is_the_sbom_purl():
    # The verdict's per-component purl must equal the same purl the SBOM
    # emits so a downstream consumer can join the two views.
    comp = _comp("openssl", "1.0.1f")
    s = _sbom(comp)
    report = component_blocklist.check(s, blocklist=["openssl"])
    assert report.components[0].purl == comp.purl()


# --- report model wiring ---------------------------------------------------


def test_report_to_dict_attaches_under_sbom_component_blocklist():
    # The Report dataclass must surface the report under sbom.component_blocklist
    # so it sits alongside sbom.licenses / sbom.vulnerabilities / etc.
    s = _sbom(_comp("openssl", "1.0.1f"))
    bl_report = component_blocklist.check(s, blocklist=["openssl"])
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.component_blocklist = bl_report
    d = report.to_dict()
    assert "sbom" in d
    assert "component_blocklist" in d["sbom"]
    assert d["sbom"]["component_blocklist"]["compliant"] is False
    assert d["sbom"]["component_blocklist"]["blocklist"] == ["openssl"]


def test_report_to_dict_omits_when_check_not_requested():
    s = _sbom(_comp("openssl", "1.0.1f"))
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    d = report.to_dict()
    # sbom is present but no component_blocklist key (the check did not run).
    assert "component_blocklist" not in d["sbom"]


# --- gate composition ------------------------------------------------------


def test_gate_observes_blocked_components_as_high_severity():
    # The --fail-on gate must count each blocked component, so pairing
    # --component-blocklist with --fail-on high trips CI on a match.
    s = _sbom(_comp("openssl", "1.0.1f"))
    bl_report = component_blocklist.check(s, blocklist=["openssl"])
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.component_blocklist = bl_report
    verdict = evaluate_gate(report, "high")
    assert verdict.triggered is True
    assert verdict.counts.get("high", 0) >= 1


def test_gate_does_not_trip_when_no_components_blocked():
    s = _sbom(_comp("safe", "1.0"))
    bl_report = component_blocklist.check(s, blocklist=["openssl"])
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.component_blocklist = bl_report
    verdict = evaluate_gate(report, "high")
    assert verdict.triggered is False


# --- markdown rendering ----------------------------------------------------


def test_markdown_renders_blocklist_subsection():
    s = _sbom(_comp("openssl", "1.0.1f"))
    bl_report = component_blocklist.check(s, blocklist=["openssl@1.0.*"])
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.component_blocklist = bl_report
    md = report_mod.render(report, "md")
    assert "### Component-blocklist compliance" in md
    assert "NOT COMPLIANT" in md
    assert "openssl@1.0.*" in md
    # The blocked-components table must list the blocked component.
    assert "| openssl | 1.0.1f |" in md


def test_markdown_renders_compliant_verdict_without_blocked_table():
    s = _sbom(_comp("safe", "1.0"))
    bl_report = component_blocklist.check(s, blocklist=["openssl"])
    report = Report(firmware="fw.bin", checks=["sbom"])
    report.sbom = s
    report.component_blocklist = bl_report
    md = report_mod.render(report, "md")
    assert "### Component-blocklist compliance" in md
    assert "COMPLIANT" in md
    assert "**Blocked components:**" not in md


# --- pipeline / CLI integration --------------------------------------------


def _planted_dpkg_fixture(tmp_path: Path) -> Path:
    """Plant a minimal extracted-firmware tree with a dpkg status DB.

    Mirrors the fixture pattern in tests/test_sbom_license.py — a single
    `var/lib/dpkg/status` file with two packages, enough for the SBOM check
    to populate two components the blocklist can score.
    """
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"fake firmware")
    # Plant the extracted tree the pipeline expects (under workdir/extract).
    extract_root = tmp_path / "work" / "extract"
    dpkg_dir = extract_root / "var" / "lib" / "dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text(
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 1.0.1f\n"
        "Architecture: amd64\n"
        "\n"
        "Package: safe-lib\n"
        "Status: install ok installed\n"
        "Version: 2.0.0\n"
        "Architecture: amd64\n"
        "\n"
    )
    return fw


def test_cli_component_blocklist_end_to_end_blocks_match(
    tmp_path, monkeypatch, capsys
):
    fw = _planted_dpkg_fixture(tmp_path)
    workdir = tmp_path / "work"

    # Stub extract.extract to return our planted tree without running unblob.
    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    def fake_extract(firmware, workdir_path, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=2,
            extraction_time_ms=0,
            extract_root=str(tmp_path / "work" / "extract"),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)

    rc = cli_main(
        [
            "--firmware",
            str(fw),
            "--workdir",
            str(workdir),
            "--checks",
            "sbom",
            "--component-blocklist",
            "openssl@1.0.*",
            "--no-enrich",
        ]
    )
    assert rc == 0  # the check itself does not change the exit code without --fail-on
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "component_blocklist" in data["sbom"]
    bl = data["sbom"]["component_blocklist"]
    assert bl["compliant"] is False
    assert bl["blocklist"] == ["openssl@1.0.*"]
    blocked_names = [c["name"] for c in bl["components"] if c["blocked"]]
    assert blocked_names == ["openssl"]


def test_cli_component_blocklist_composes_with_fail_on_gate(
    tmp_path, monkeypatch, capsys
):
    # Pair --component-blocklist with --fail-on high: a blocklist match must
    # cause the CLI to exit with code 10 (the gate exit code).
    fw = _planted_dpkg_fixture(tmp_path)
    workdir = tmp_path / "work"

    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    def fake_extract(firmware, workdir_path, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=2,
            extraction_time_ms=0,
            extract_root=str(tmp_path / "work" / "extract"),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)

    rc = cli_main(
        [
            "--firmware",
            str(fw),
            "--workdir",
            str(workdir),
            "--checks",
            "sbom",
            "--component-blocklist",
            "openssl",
            "--fail-on",
            "high",
            "--no-enrich",
        ]
    )
    assert rc == GATE_EXIT_CODE


def test_cli_component_blocklist_compliant_run_does_not_trip_gate(
    tmp_path, monkeypatch, capsys
):
    # A blocklist that does not match any component must leave the gate
    # quiet (every existing exit code byte-for-byte unchanged).
    fw = _planted_dpkg_fixture(tmp_path)
    workdir = tmp_path / "work"

    from embalmer import extract as extract_mod
    from embalmer.models import ExtractionResult

    def fake_extract(firmware, workdir_path, extractor="auto"):
        return ExtractionResult(
            extraction_tree={},
            file_count=2,
            extraction_time_ms=0,
            extract_root=str(tmp_path / "work" / "extract"),
            extractor_used="unblob",
        )

    monkeypatch.setattr(extract_mod, "extract", fake_extract)

    rc = cli_main(
        [
            "--firmware",
            str(fw),
            "--workdir",
            str(workdir),
            "--checks",
            "sbom",
            "--component-blocklist",
            "log4j",  # not in the planted fixture
            "--fail-on",
            "high",
            "--no-enrich",
        ]
    )
    assert rc == 0
