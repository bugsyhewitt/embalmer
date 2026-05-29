"""Tests for the severity gate (`--fail-on` CI exit-code policy).

Two layers of coverage:

* Unit tests of :func:`embalmer.gate.evaluate` over hand-built
  :class:`Report` objects, exercising every threshold tier, the inclusive
  threshold semantics, the unknown-severity-skip rule, SBOM CVE participation,
  and the ``GateResult`` summary line.
* CLI tests of ``--fail-on`` exercising the argparse plumbing, the new
  exit-code 10, the "report still emitted" guarantee, and the stderr summary
  line — driven through ``embalmer.cli.main`` against the same fixture the
  smoke tests use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from embalmer import extract
from embalmer.cli import main
from embalmer.gate import (
    FAIL_ON_CHOICES,
    GATE_EXIT_CODE,
    GateResult,
    evaluate,
)
from embalmer.models import Finding, Report
from embalmer.sbom_cve import CveMatch, SbomCveReport


# ---------------------------------------------------------------------------
# unit tests: gate.evaluate over hand-built Report objects
# ---------------------------------------------------------------------------


def _report_with(**findings_by_section) -> Report:
    """Build a minimal Report carrying just the named finding sections."""
    return Report(
        firmware="test.bin",
        checks=["creds", "certs", "binaries", "components"],
        **findings_by_section,
    )


def _f(severity: str, *, category: str = "credential", path: str = "/etc/x") -> Finding:
    return Finding(
        category=category,
        path=path,
        type="t",
        detail="d",
        severity=severity,
    )


class TestEvaluateThresholds:
    def test_none_threshold_never_triggers(self):
        report = _report_with(
            credentials=[_f("critical"), _f("high"), _f("info")]
        )
        result = evaluate(report, "none")
        assert result.triggered is False
        # Counts are still populated so a 'report-only' run can log the tally.
        assert result.counts == {"critical": 1, "high": 1, "info": 1}

    def test_critical_threshold_triggers_only_on_critical(self):
        report_high = _report_with(credentials=[_f("high"), _f("medium")])
        assert evaluate(report_high, "critical").triggered is False
        report_crit = _report_with(credentials=[_f("critical")])
        assert evaluate(report_crit, "critical").triggered is True

    def test_high_threshold_is_inclusive_of_critical(self):
        # High fails on high AND critical.
        report = _report_with(credentials=[_f("critical"), _f("low")])
        result = evaluate(report, "high")
        assert result.triggered is True

    def test_medium_threshold_does_not_trigger_on_low_or_info(self):
        report = _report_with(credentials=[_f("low"), _f("info")])
        assert evaluate(report, "medium").triggered is False
        report2 = _report_with(credentials=[_f("medium"), _f("info")])
        assert evaluate(report2, "medium").triggered is True

    def test_info_threshold_triggers_on_any_finding(self):
        report = _report_with(credentials=[_f("info")])
        assert evaluate(report, "info").triggered is True

    def test_empty_report_never_triggers(self):
        report = Report(firmware="x.bin", checks=[])
        for threshold in ("info", "low", "medium", "high", "critical"):
            assert evaluate(report, threshold).triggered is False
        assert evaluate(report, "none").counts == {}

    def test_unknown_severity_is_ignored(self):
        # A finding with a non-ladder severity must not count toward the gate.
        report = _report_with(
            credentials=[_f("super-bad"), _f("unknown"), _f("low")]
        )
        result = evaluate(report, "low")
        assert result.triggered is True  # the 'low' alone is enough
        # And the unknown tiers must not show up in counts.
        assert "super-bad" not in result.counts
        assert "unknown" not in result.counts
        assert result.counts == {"low": 1}

    def test_unknown_threshold_raises(self):
        report = _report_with(credentials=[_f("high")])
        with pytest.raises(ValueError):
            evaluate(report, "bogus")


class TestEvaluateAllSections:
    def test_walks_every_finding_section(self):
        report = _report_with(
            credentials=[_f("low", category="credential", path="/etc/shadow")],
            certificates=[_f("medium", category="certificate", path="/x.pem")],
            binaries=[_f("high", category="binary", path="/bin/x")],
            components=[_f("info", category="component", path="/lib/x")],
        )
        result = evaluate(report, "info")
        assert result.counts == {
            "info": 1,
            "low": 1,
            "medium": 1,
            "high": 1,
        }
        assert result.triggered is True

    def test_sbom_cve_matches_participate_in_gate(self):
        # An SBOM CVE match with severity=critical alone should trigger 'critical'.
        report = _report_with(credentials=[])
        report.sbom_cve = SbomCveReport(
            matches=[
                CveMatch(
                    cve_id="CVE-2014-0160",
                    purl="pkg:generic/openssl@1.0.1f",
                    cvss=7.5,
                    severity="critical",
                    in_kev=True,
                )
            ],
            components_checked=1,
        )
        # The Report needs an sbom to render sbom.vulnerabilities — populate
        # a minimal stub via the dict path the gate reads.
        from embalmer.sbom import Sbom
        report.sbom = Sbom(components=[])
        result = evaluate(report, "critical")
        assert result.triggered is True
        assert result.counts == {"critical": 1}

    def test_offending_count_only_counts_at_or_above_threshold(self):
        report = _report_with(credentials=[
            _f("critical"), _f("high"), _f("medium"), _f("low"), _f("info")
        ])
        # high threshold => critical + high count, not medium/low/info.
        result = evaluate(report, "high")
        assert result.offending_count == 2

    def test_offending_count_zero_when_none(self):
        report = _report_with(credentials=[_f("high")])
        assert evaluate(report, "none").offending_count == 0


class TestGateResultSummaryLine:
    def test_no_findings(self):
        result = GateResult(threshold="high", triggered=False, counts={})
        line = result.summary_line()
        assert "fail-on=high" in line
        assert "ok" in line
        assert "no findings" in line

    def test_ladder_order_in_summary(self):
        # Tally must read critical -> info regardless of insertion order.
        result = GateResult(
            threshold="medium",
            triggered=True,
            counts={"info": 3, "critical": 1, "high": 2, "medium": 5},
        )
        line = result.summary_line()
        # critical comes before high, high before medium, medium before info.
        assert line.index("critical=1") < line.index("high=2")
        assert line.index("high=2") < line.index("medium=5")
        assert line.index("medium=5") < line.index("info=3")
        assert "TRIGGERED" in line

    def test_omits_zero_buckets(self):
        result = GateResult(
            threshold="high",
            triggered=True,
            counts={"critical": 1, "high": 0, "low": 0},
        )
        line = result.summary_line()
        assert "critical=1" in line
        # Zero buckets must not appear at all.
        assert "high=" not in line
        assert "low=" not in line


# ---------------------------------------------------------------------------
# CLI tests: --fail-on plumbing through main()
# ---------------------------------------------------------------------------


def _plant_minimal_tree(workdir: Path) -> None:
    """Same shape as test_smoke._plant_fixture_tree but minimal — one cred
    that the scanner will tag as 'high' so the gate has something to score."""
    base = workdir / "sample-firmware.bin_extract"
    (base / "etc").mkdir(parents=True)
    (base / "etc" / "shadow").write_text(
        "root:$6$saltsalt$3xampleHash:19000:0:99999:7:::\n"
    )
    (base / "etc" / "sample.conf").write_text(
        "admin_password=SuperSecret123\n"
    )


@pytest.fixture
def _mock_extract(monkeypatch):
    monkeypatch.setattr(
        extract, "_run_unblob", lambda fw, wd: _plant_minimal_tree(wd)
    )


def _run_cli(args, capsys, monkeypatch):
    """Drive embalmer.cli.main with the given args, return (rc, stdout, stderr)."""
    rc = main(args)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


class TestCliFailOnFlag:
    def test_default_is_none_no_gate_no_extra_stderr(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        rc, stdout, stderr = _run_cli(
            [
                "--firmware", str(sample_firmware),
                "--workdir", str(tmp_path / "w"),
                "--checks", "creds",
                "--no-enrich",
            ],
            capsys,
            None,
        )
        assert rc == 0
        # Without --fail-on the gate's summary line MUST NOT appear in stderr.
        assert "fail-on=" not in stderr

    def test_fail_on_high_triggers_when_high_finding_present(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        rc, stdout, stderr = _run_cli(
            [
                "--firmware", str(sample_firmware),
                "--workdir", str(tmp_path / "w"),
                "--checks", "creds",
                "--no-enrich",
                "--fail-on", "high",
            ],
            capsys,
            None,
        )
        # The bundled creds (shadow hash etc.) include 'high' tier findings.
        assert rc == GATE_EXIT_CODE
        assert "fail-on=high" in stderr
        assert "TRIGGERED" in stderr
        # The report itself must still be on stdout (the gate observes, never
        # suppresses) — should be valid JSON.
        json.loads(stdout)

    def test_fail_on_critical_does_not_trigger_on_high_only(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        rc, stdout, stderr = _run_cli(
            [
                "--firmware", str(sample_firmware),
                "--workdir", str(tmp_path / "w"),
                "--checks", "creds",
                "--no-enrich",
                "--fail-on", "critical",
            ],
            capsys,
            None,
        )
        # Stock creds don't reach 'critical' without CVE enrichment.
        assert rc == 0
        # But the summary line is still emitted so the run is auditable.
        assert "fail-on=critical" in stderr
        assert "[ok]" in stderr

    def test_fail_on_none_disables_gate_explicitly(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        rc, stdout, stderr = _run_cli(
            [
                "--firmware", str(sample_firmware),
                "--workdir", str(tmp_path / "w"),
                "--checks", "creds",
                "--no-enrich",
                "--fail-on", "none",
            ],
            capsys,
            None,
        )
        # Even when explicitly passed, 'none' must behave like the default and
        # never trigger / never log.
        assert rc == 0
        assert "fail-on=" not in stderr

    def test_fail_on_rejects_unknown_tier(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        # argparse choice validation should reject and exit 2.
        with pytest.raises(SystemExit) as exc:
            main(
                [
                    "--firmware", str(sample_firmware),
                    "--workdir", str(tmp_path / "w"),
                    "--checks", "creds",
                    "--fail-on", "scary",
                ]
            )
        assert exc.value.code == 2  # argparse usage exit

    def test_fail_on_with_output_file_still_writes_report(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        out = tmp_path / "report.json"
        rc, stdout, stderr = _run_cli(
            [
                "--firmware", str(sample_firmware),
                "--workdir", str(tmp_path / "w"),
                "--checks", "creds",
                "--no-enrich",
                "--fail-on", "high",
                "--output", str(out),
            ],
            capsys,
            None,
        )
        # The gate trips, but the report file is still written and parseable.
        assert rc == GATE_EXIT_CODE
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["firmware"] == str(sample_firmware)

    def test_all_documented_choices_are_accepted(
        self, sample_firmware, tmp_path, capsys, _mock_extract
    ):
        # Sanity: every value in FAIL_ON_CHOICES must be argparse-accepted.
        for choice in FAIL_ON_CHOICES:
            rc, _, _ = _run_cli(
                [
                    "--firmware", str(sample_firmware),
                    "--workdir", str(tmp_path / f"w-{choice}"),
                    "--checks", "extract",
                    "--no-enrich",
                    "--fail-on", choice,
                ],
                capsys,
                None,
            )
            # 'extract' alone produces no findings, so even 'info' must pass.
            assert rc == 0, f"choice {choice!r} unexpectedly failed (rc={rc})"
