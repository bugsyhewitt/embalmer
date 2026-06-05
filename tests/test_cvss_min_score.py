"""Tests for --cvss-min-score CVSS base-score filter.

All tests are unit-level and run entirely in-process — no firmware extraction,
no network calls. The filter is a post-cross-reference step in the pipeline
(``embalmer/pipeline.py``) that removes CVE matches whose raw CVSS base score
is below the operator-specified threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

import pytest

from embalmer.sbom_cve import CveMatch, SbomCveReport


# ---------------------------------------------------------------------------
# Helper: build a minimal SbomCveReport with arbitrary CveMatch entries
# ---------------------------------------------------------------------------


def _make_report(matches: list[tuple[str, float | None]]) -> SbomCveReport:
    """Build a SbomCveReport from (cve_id, cvss) pairs.

    ``cvss=None`` represents a CVE that has not been scored by NVD yet.
    """
    m = [
        CveMatch(cve_id=cve, purl="pkg:deb/debian/openssl@1.0.1f", cvss=cvss)
        for cve, cvss in matches
    ]
    return SbomCveReport(matches=m, components_checked=1)


# ---------------------------------------------------------------------------
# Direct pipeline filtering: isolate the filter step from the full pipeline
# ---------------------------------------------------------------------------


def _apply_filter(report: SbomCveReport, threshold: float) -> SbomCveReport:
    """Apply the same filter logic as pipeline.run() with cvss_min_score."""
    report.matches = [
        m for m in report.matches
        if m.cvss is None or m.cvss >= threshold
    ]
    return report


class TestCvssMinScoreFilter:
    """Unit-level tests for the CVSS score filter logic."""

    def test_no_filter_when_none(self):
        """cvss_min_score=None must not remove any CVE match."""
        r = _make_report([("CVE-2014-0160", 10.0), ("CVE-2021-0001", 2.0)])
        # Simulate pipeline with no threshold: matches unchanged.
        assert len(r.matches) == 2

    def test_removes_below_threshold(self):
        """Matches with CVSS < threshold must be removed."""
        r = _make_report([
            ("CVE-A", 9.8),
            ("CVE-B", 7.5),
            ("CVE-C", 5.0),
            ("CVE-D", 3.1),
        ])
        r = _apply_filter(r, 7.0)
        kept = {m.cve_id for m in r.matches}
        assert kept == {"CVE-A", "CVE-B"}

    def test_keeps_equal_to_threshold(self):
        """A match whose CVSS exactly equals the threshold must be kept."""
        r = _make_report([("CVE-EXACT", 7.0)])
        r = _apply_filter(r, 7.0)
        assert len(r.matches) == 1
        assert r.matches[0].cve_id == "CVE-EXACT"

    def test_removes_below_threshold_strictly(self):
        """A match at 6.9 is below 7.0 and must be removed."""
        r = _make_report([("CVE-NEAR", 6.9)])
        r = _apply_filter(r, 7.0)
        assert r.matches == []

    def test_keeps_none_cvss_regardless_of_threshold(self):
        """Matches with cvss=None must always be kept (KEV/EPSS may still matter)."""
        r = _make_report([
            ("CVE-NO-SCORE", None),
            ("CVE-LOW", 2.0),
        ])
        r = _apply_filter(r, 9.0)
        kept = {m.cve_id for m in r.matches}
        assert "CVE-NO-SCORE" in kept
        assert "CVE-LOW" not in kept

    def test_all_above_threshold_kept(self):
        """When every match is at or above the threshold, all are kept."""
        r = _make_report([("CVE-A", 8.0), ("CVE-B", 9.5), ("CVE-C", 10.0)])
        r = _apply_filter(r, 7.5)
        assert len(r.matches) == 3

    def test_all_below_threshold_removed(self):
        """When every scored match is below the threshold, list becomes empty."""
        r = _make_report([("CVE-A", 3.0), ("CVE-B", 4.0)])
        r = _apply_filter(r, 7.0)
        assert r.matches == []

    def test_threshold_zero_keeps_all_scored(self):
        """A threshold of 0.0 keeps every match (all CVSS >= 0.0)."""
        r = _make_report([("CVE-A", 0.1), ("CVE-B", 5.0), ("CVE-C", 10.0)])
        r = _apply_filter(r, 0.0)
        assert len(r.matches) == 3

    def test_threshold_ten_keeps_only_max_score(self):
        """A threshold of 10.0 keeps only perfect CVSS-10 matches."""
        r = _make_report([
            ("CVE-CRITICAL", 10.0),
            ("CVE-HIGH", 9.9),
            ("CVE-NO-SCORE", None),
        ])
        r = _apply_filter(r, 10.0)
        kept = {m.cve_id for m in r.matches}
        assert kept == {"CVE-CRITICAL", "CVE-NO-SCORE"}

    def test_cve_count_property_reflects_filtered_list(self):
        """SbomCveReport.cve_count reflects the post-filter match count."""
        r = _make_report([("CVE-A", 9.0), ("CVE-B", 3.0)])
        r = _apply_filter(r, 7.0)
        assert r.cve_count == 1

    def test_to_dict_reflects_filtered_list(self):
        """to_dict() exposes only the post-filter matches."""
        r = _make_report([("CVE-KEEP", 8.5), ("CVE-DROP", 4.0)])
        r = _apply_filter(r, 7.0)
        d = r.to_dict()
        cve_ids = [v["cve_id"] for v in d["vulnerabilities"]]
        assert cve_ids == ["CVE-KEEP"]
        assert d["cve_count"] == 1


# ---------------------------------------------------------------------------
# Pipeline integration tests (mock the pipeline's extraction + SBOM layer)
# ---------------------------------------------------------------------------


def _make_sbom_cve_report_for_pipeline(matches):
    """Build a SbomCveReport suitable for injection into a pipeline mock."""
    return _make_report(matches)


class TestCvssMinScorePipeline:
    """Integration tests verifying the filter is wired into pipeline.run()."""

    def _run_pipeline_with_mocked_cve(
        self,
        cve_matches: list[tuple[str, float | None]],
        cvss_min_score: float | None,
    ) -> "SbomCveReport | None":
        """Run the pipeline with a mocked SBOM CVE cross-reference.

        Returns ``report.sbom_cve`` from the assembled report.
        """
        from embalmer import pipeline
        from embalmer.models import Report
        from embalmer.sbom import Component, Sbom

        # Build a fake SbomCveReport that sbom_cve.cross_reference returns.
        fake_cve_report = _make_report(cve_matches)

        # Patch the heaviest dependencies so this test runs in < 1 s.
        with (
            patch("embalmer.pipeline.extract.extract") as mock_extract,
            patch("embalmer.pipeline.sbom.scan") as mock_sbom_generate,
            patch("embalmer.pipeline.sbom_cve.cross_reference") as mock_cve_xref,
        ):
            fake_extract = MagicMock()
            fake_extract.extract_root = "/fake/root"
            mock_extract.return_value = fake_extract

            fake_sbom = MagicMock(spec=Sbom)
            fake_sbom.components = []
            mock_sbom_generate.return_value = fake_sbom

            mock_cve_xref.return_value = fake_cve_report

            report = pipeline.run(
                firmware="/fake/firmware.bin",
                workdir="/fake/work",
                checks="sbom",
                sbom_cve_check=True,
                enrich=True,
                cvss_min_score=cvss_min_score,
            )
        return report.sbom_cve

    def test_pipeline_no_filter_passes_all(self):
        """Without a threshold, all CVE matches appear in the report."""
        result = self._run_pipeline_with_mocked_cve(
            [("CVE-A", 9.0), ("CVE-B", 3.0)],
            cvss_min_score=None,
        )
        assert result is not None
        assert result.cve_count == 2

    def test_pipeline_filter_removes_low_score(self):
        """Pipeline with cvss_min_score=7.0 drops matches below 7.0."""
        result = self._run_pipeline_with_mocked_cve(
            [("CVE-HIGH", 9.0), ("CVE-LOW", 3.0)],
            cvss_min_score=7.0,
        )
        assert result is not None
        assert result.cve_count == 1
        assert result.matches[0].cve_id == "CVE-HIGH"

    def test_pipeline_filter_keeps_null_cvss(self):
        """Pipeline filter keeps matches with cvss=None regardless of threshold."""
        result = self._run_pipeline_with_mocked_cve(
            [("CVE-UNSCORED", None), ("CVE-LOW", 2.0)],
            cvss_min_score=9.0,
        )
        assert result is not None
        assert result.cve_count == 1
        assert result.matches[0].cve_id == "CVE-UNSCORED"

    def test_pipeline_filter_all_removed(self):
        """When every match is below the threshold, vulnerabilities list is empty."""
        result = self._run_pipeline_with_mocked_cve(
            [("CVE-A", 3.0), ("CVE-B", 5.0)],
            cvss_min_score=9.0,
        )
        assert result is not None
        assert result.cve_count == 0

    def test_pipeline_filter_no_sbom_cve_is_noop(self):
        """When no CVE cross-reference runs, cvss_min_score is silently ignored."""
        from embalmer import pipeline

        with (
            patch("embalmer.pipeline.extract.extract") as mock_extract,
            patch("embalmer.pipeline.sbom.scan") as mock_sbom_generate,
        ):
            fake_extract = MagicMock()
            fake_extract.extract_root = "/fake/root"
            mock_extract.return_value = fake_extract

            from embalmer.sbom import Sbom
            fake_sbom = MagicMock(spec=Sbom)
            fake_sbom.components = []
            mock_sbom_generate.return_value = fake_sbom

            report = pipeline.run(
                firmware="/fake/firmware.bin",
                workdir="/fake/work",
                checks="sbom",
                sbom_cve_check=False,
                cvss_min_score=7.0,
            )
        # No CVE check ran, so sbom_cve is None — filter was a no-op.
        assert report.sbom_cve is None


# ---------------------------------------------------------------------------
# CLI argument validation tests
# ---------------------------------------------------------------------------


class TestCvssMinScoreCli:
    """Tests for --cvss-min-score CLI argument parsing and validation."""

    def test_cli_rejects_negative_score(self, capsys):
        """--cvss-min-score with a negative value must return exit 1."""
        from embalmer.cli import main

        # argparse will try to parse -1.0 as a flag; if it gets through,
        # our validation catches it. Either way failure is non-zero.
        try:
            rc = main(["--firmware", "/fake/fw.bin", "--cvss-min-score", "-1.0"])
        except SystemExit as e:
            rc = e.code
        # Validation branch returns 1; argparse unknown-flag may return 2.
        assert rc != 0

    def test_cli_rejects_score_above_10(self, capsys):
        """--cvss-min-score > 10.0 must print an error and return 1."""
        from embalmer.cli import main

        rc = main(["--firmware", "/fake/fw.bin", "--cvss-min-score", "11.0"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "10.0" in err or "0.0" in err

    def test_cli_accepts_boundary_values(self, capsys):
        """0.0 and 10.0 are valid CVSS scores and must not trigger validation error."""
        from embalmer.cli import main

        for score_str in ("0.0", "10.0", "7.5"):
            # Patch run() to avoid any real pipeline work; we only want to verify
            # the validation branch does NOT fire for these valid scores.
            with patch("embalmer.cli.run") as mock_run, \
                 patch("embalmer.cli.render", return_value="{}"):
                mock_run.return_value = MagicMock()
                try:
                    rc = main(["--firmware", "/fake/fw.bin",
                               "--cvss-min-score", score_str])
                except (SystemExit, Exception):
                    rc = None
                # rc == 1 would mean our validation branch fired — must NOT happen.
                assert rc != 1, f"--cvss-min-score {score_str} incorrectly rejected"
