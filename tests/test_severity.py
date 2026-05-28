"""Tests for CVSS/EPSS/KEV multi-factor severity scoring.

All HTTP calls are mocked — no real network access is made.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from embalmer.severity import (
    SeverityScore,
    _reset_kev_cache,
    score_cve,
    score_cwe,
)


# ---------------------------------------------------------------------------
# Helpers to build fake NVD / EPSS / KEV payloads
# ---------------------------------------------------------------------------


def _nvd_cve_item(cve_id: str, cvss_score: float | None) -> dict:
    """Build a minimal NVD cve item dict."""
    metrics: dict = {}
    if cvss_score is not None:
        metrics["cvssMetricV31"] = [
            {
                "cvssData": {
                    "baseScore": cvss_score,
                    "version": "3.1",
                },
            }
        ]
    return {"id": cve_id, "metrics": metrics}


def _nvd_response(cve_items: list[dict]) -> dict:
    return {
        "vulnerabilities": [{"cve": item} for item in cve_items],
        "totalResults": len(cve_items),
    }


def _epss_response(cve_id: str, epss_score: float) -> dict:
    return {"data": [{"cve": cve_id, "epss": str(epss_score), "percentile": "0.9"}]}


def _kev_response(cve_ids: list[str]) -> dict:
    return {
        "title": "CISA KEV Catalog",
        "vulnerabilities": [{"cveID": cid} for cid in cve_ids],
    }


# ---------------------------------------------------------------------------
# SeverityScore unit tests (no I/O)
# ---------------------------------------------------------------------------


class TestSeverityScoreLabel:
    def test_kev_membership_is_critical_regardless_of_cvss(self):
        label = SeverityScore.compute_label(cvss=3.0, in_kev=True)
        assert label == "critical"

    def test_kev_membership_no_cvss_is_critical(self):
        label = SeverityScore.compute_label(cvss=None, in_kev=True)
        assert label == "critical"

    def test_cvss_9_0_is_critical(self):
        assert SeverityScore.compute_label(cvss=9.0, in_kev=False) == "critical"

    def test_cvss_9_8_is_critical(self):
        assert SeverityScore.compute_label(cvss=9.8, in_kev=False) == "critical"

    def test_cvss_7_0_is_high(self):
        assert SeverityScore.compute_label(cvss=7.0, in_kev=False) == "high"

    def test_cvss_8_9_is_high(self):
        assert SeverityScore.compute_label(cvss=8.9, in_kev=False) == "high"

    def test_cvss_4_0_is_medium(self):
        assert SeverityScore.compute_label(cvss=4.0, in_kev=False) == "medium"

    def test_cvss_6_9_is_medium(self):
        assert SeverityScore.compute_label(cvss=6.9, in_kev=False) == "medium"

    def test_cvss_3_9_is_low(self):
        assert SeverityScore.compute_label(cvss=3.9, in_kev=False) == "low"

    def test_no_cvss_not_kev_is_info(self):
        assert SeverityScore.compute_label(cvss=None, in_kev=False) == "info"


class TestEpssPromotion:
    """EPSS at/above the promotion threshold bumps the base CVSS tier one rung."""

    def test_low_epss_does_not_promote(self):
        # CVSS 6.0 -> medium; low EPSS leaves it medium.
        assert SeverityScore.compute_label(cvss=6.0, in_kev=False, epss=0.01) == "medium"

    def test_high_epss_promotes_medium_to_high(self):
        # CVSS 6.0 -> medium; EPSS 0.7 (likely exploited) -> high.
        assert SeverityScore.compute_label(cvss=6.0, in_kev=False, epss=0.7) == "high"

    def test_high_epss_promotes_low_to_medium(self):
        # CVSS 2.0 -> low; high EPSS -> medium.
        assert SeverityScore.compute_label(cvss=2.0, in_kev=False, epss=0.9) == "medium"

    def test_high_epss_promotes_high_to_critical(self):
        # CVSS 7.5 -> high; high EPSS -> critical.
        assert SeverityScore.compute_label(cvss=7.5, in_kev=False, epss=0.6) == "critical"

    def test_epss_exactly_at_threshold_promotes(self):
        # Boundary: EPSS == 0.5 must promote (>= comparison).
        assert SeverityScore.compute_label(cvss=4.0, in_kev=False, epss=0.5) == "high"

    def test_epss_just_below_threshold_does_not_promote(self):
        assert SeverityScore.compute_label(cvss=4.0, in_kev=False, epss=0.4999) == "medium"

    def test_critical_is_not_promoted_past_critical(self):
        # CVSS 9.5 is already critical; high EPSS cannot escalate further.
        assert SeverityScore.compute_label(cvss=9.5, in_kev=False, epss=0.99) == "critical"

    def test_info_is_not_promoted_on_epss_alone(self):
        # No CVSS data -> info; EPSS without an actionable score stays info.
        assert SeverityScore.compute_label(cvss=None, in_kev=False, epss=0.99) == "info"

    def test_kev_stays_critical_regardless_of_epss(self):
        assert SeverityScore.compute_label(cvss=3.0, in_kev=True, epss=0.0) == "critical"

    def test_epss_none_behaves_like_no_promotion(self):
        # Backwards-compatible default: omitting EPSS keeps the base label.
        assert SeverityScore.compute_label(cvss=6.0, in_kev=False) == "medium"
        assert SeverityScore.compute_label(cvss=6.0, in_kev=False, epss=None) == "medium"


class TestSeverityScoreToDict:
    def test_to_dict_includes_label_and_in_kev(self):
        s = SeverityScore(cvss=7.5, epss=0.03, in_kev=False, label="high", cve_id="CVE-2021-1234")
        d = s.to_dict()
        assert d["label"] == "high"
        assert d["in_kev"] is False
        assert d["cvss"] == 7.5
        assert d["epss"] == 0.03
        assert d["cve_id"] == "CVE-2021-1234"

    def test_to_dict_omits_none_fields(self):
        s = SeverityScore(cvss=None, epss=None, in_kev=False, label="info")
        d = s.to_dict()
        assert "cvss" not in d
        assert "epss" not in d
        assert "cve_id" not in d

    def test_to_dict_includes_epss_promoted_when_set(self):
        s = SeverityScore(
            cvss=6.0, epss=0.7, in_kev=False, label="high",
            cve_id="CVE-2021-1234", epss_promoted=True,
        )
        d = s.to_dict()
        assert d["epss_promoted"] is True
        assert d["label"] == "high"

    def test_to_dict_omits_epss_promoted_when_false(self):
        s = SeverityScore(cvss=7.5, epss=0.01, in_kev=False, label="high")
        d = s.to_dict()
        assert "epss_promoted" not in d


# ---------------------------------------------------------------------------
# score_cve tests
# ---------------------------------------------------------------------------


class TestScoreCve:
    def setup_method(self):
        _reset_kev_cache()

    def _mock_fetch(self, url_map: dict):
        """Return a side_effect fn for _fetch_json that looks up by URL substring."""
        def _side(url, timeout=10):
            for key, val in url_map.items():
                if key in url:
                    return val
            return None
        return _side

    def test_kev_member_gives_critical(self):
        cve_id = "CVE-2021-44228"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=10.0)])
        epss_data = _epss_response(cve_id, 0.97)
        kev_data = _kev_response([cve_id])

        fetch_map = {
            "nvd.nist.gov": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cve(cve_id)

        assert result.label == "critical"
        assert result.in_kev is True
        assert result.cvss == 10.0

    def test_high_cvss_gives_high_when_not_in_kev(self):
        cve_id = "CVE-2020-0001"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=7.8)])
        epss_data = _epss_response(cve_id, 0.05)
        kev_data = _kev_response([])

        fetch_map = {
            "nvd.nist.gov": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cve(cve_id)

        assert result.label == "high"
        assert result.in_kev is False
        assert result.cvss == 7.8

    def test_no_data_available_returns_graceful_info(self):
        """When all network calls return None, score_cve must not raise."""
        with patch("embalmer.severity._fetch_json", return_value=None):
            result = score_cve("CVE-9999-0000")

        assert result.label == "info"
        assert result.cvss is None
        assert result.epss is None
        assert result.in_kev is False

    def test_cve_id_is_propagated(self):
        cve_id = "CVE-2022-12345"
        with patch("embalmer.severity._fetch_json", return_value=None):
            result = score_cve(cve_id)
        assert result.cve_id == cve_id

    def test_high_epss_promotes_medium_cve_to_high(self):
        """A CVSS-6.0 CVE with EPSS 0.8 is triaged as high, flagged promoted."""
        cve_id = "CVE-2023-5555"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=6.0)])
        epss_data = _epss_response(cve_id, 0.8)
        kev_data = _kev_response([])

        fetch_map = {
            "nvd.nist.gov": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cve(cve_id)

        assert result.cvss == 6.0
        assert result.epss == 0.8
        assert result.label == "high"
        assert result.epss_promoted is True

    def test_low_epss_leaves_label_unpromoted(self):
        cve_id = "CVE-2023-6666"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=6.0)])
        epss_data = _epss_response(cve_id, 0.02)
        kev_data = _kev_response([])

        fetch_map = {
            "nvd.nist.gov": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cve(cve_id)

        assert result.label == "medium"
        assert result.epss_promoted is False


# ---------------------------------------------------------------------------
# score_cwe tests
# ---------------------------------------------------------------------------


class TestScoreCwe:
    def setup_method(self):
        _reset_kev_cache()

    def _mock_fetch(self, url_map: dict):
        def _side(url, timeout=10):
            for key, val in url_map.items():
                if key in url:
                    return val
            return None
        return _side

    def test_kev_membership_gives_critical(self):
        cve_id = "CVE-2021-44228"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=10.0)])
        epss_data = _epss_response(cve_id, 0.97)
        kev_data = _kev_response([cve_id])

        fetch_map = {
            "cweId": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cwe(120)

        assert result is not None
        assert result.label == "critical"
        assert result.in_kev is True

    def test_high_cvss_gives_high_label(self):
        cve_id = "CVE-2019-9999"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=8.1)])
        epss_data = _epss_response(cve_id, 0.10)
        kev_data = _kev_response([])

        fetch_map = {
            "cweId": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cwe(78)

        assert result is not None
        assert result.label == "high"
        assert result.cvss == 8.1

    def test_no_nvd_data_returns_none(self):
        """When NVD returns no CVEs for a CWE, score_cwe must return None."""
        kev_data = _kev_response([])
        fetch_map = {
            "cweId": _nvd_response([]),
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cwe(9999)

        assert result is None

    def test_all_network_fails_returns_none(self):
        """Complete network failure: score_cwe returns None gracefully."""
        with patch("embalmer.severity._fetch_json", return_value=None):
            result = score_cwe(120)
        assert result is None

    def test_picks_max_cvss_from_multiple_cves(self):
        """score_cwe uses the CVE with the highest CVSS score."""
        cve_low = _nvd_cve_item("CVE-2020-0001", 4.0)
        cve_high = _nvd_cve_item("CVE-2020-0002", 9.8)
        nvd_data = _nvd_response([cve_low, cve_high])
        epss_data = _epss_response("CVE-2020-0002", 0.5)
        kev_data = _kev_response([])

        fetch_map = {
            "cweId": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cwe(120)

        assert result is not None
        assert result.cvss == 9.8
        assert result.cve_id == "CVE-2020-0002"

    def test_high_epss_promotes_cwe_label(self):
        """A CWE whose worst CVE is CVSS 6.5 + EPSS 0.9 triages high."""
        cve_id = "CVE-2024-7777"
        nvd_data = _nvd_response([_nvd_cve_item(cve_id, cvss_score=6.5)])
        epss_data = _epss_response(cve_id, 0.9)
        kev_data = _kev_response([])

        fetch_map = {
            "cweId": nvd_data,
            "api.first.org": epss_data,
            "cisa.gov": kev_data,
        }
        with patch("embalmer.severity._fetch_json", side_effect=self._mock_fetch(fetch_map)):
            result = score_cwe(787)

        assert result is not None
        assert result.cvss == 6.5
        assert result.label == "high"
        assert result.epss_promoted is True


# ---------------------------------------------------------------------------
# Stubs for modules that may not be installed (binary_finding_schema etc.)
# ---------------------------------------------------------------------------

import sys
import types as _types


def _ensure_binary_stubs():
    """Inject minimal stubs so tests can import embalmer.pipeline / cli."""
    if "binary_finding_schema" not in sys.modules:
        bfs = _types.ModuleType("binary_finding_schema")

        class BinaryFinding:
            def __init__(self, *, cwe_id="CWE-0", function=None, address=None,
                         evidence="", symbol=None):
                self.cwe_id = cwe_id
                self.function = function
                self.address = address
                self.evidence = evidence
                self.symbol = symbol

        bfs.BinaryFinding = BinaryFinding
        sys.modules["binary_finding_schema"] = bfs

    if "binary_pipeline" not in sys.modules:
        bp = _types.ModuleType("binary_pipeline")
        bps = _types.ModuleType("binary_pipeline._subprocess")

        class SubprocessAnalyzerError(Exception):
            pass

        class SubprocessAnalyzer:
            pass

        bps.SubprocessAnalyzerError = SubprocessAnalyzerError
        bp.find_binaries = lambda root: []
        bp.run_pipeline = lambda bins, analyzers: []
        bp.SubprocessAnalyzer = SubprocessAnalyzer
        sys.modules["binary_pipeline"] = bp
        sys.modules["binary_pipeline._subprocess"] = bps


# ---------------------------------------------------------------------------
# Pipeline integration: --no-enrich flag
# ---------------------------------------------------------------------------


class TestNoEnrich:
    """Verify that enrich=False skips scoring entirely."""

    def setup_method(self):
        _reset_kev_cache()
        _ensure_binary_stubs()

    def test_no_enrich_skips_severity_score(self, fake_extracted_tree):
        """When enrich=False, binary findings have no severity_score extra field."""
        BinaryFinding = sys.modules["binary_finding_schema"].BinaryFinding

        from embalmer.pipeline import run
        from embalmer.models import ExtractionResult, Finding

        fake_result = ExtractionResult(
            extraction_tree={},
            file_count=2,
            extraction_time_ms=1,
            extract_root=str(fake_extracted_tree / "sample-firmware.bin_extract"),
        )

        # Inject a pre-built list of binary findings directly — bypasses blight.
        sample_findings = [
            Finding(category="binary", path="bin/busybox", type="CWE-120",
                    detail="overflow", severity="info"),
        ]

        with patch("embalmer.pipeline.extract.extract", return_value=fake_result), \
             patch("embalmer.pipeline.binaries.analyze", return_value=sample_findings):
            report = run(
                firmware="fake.bin",
                workdir="/tmp",
                checks="binaries",
                enrich=False,
            )

        assert report.binaries is not None
        for f in report.binaries:
            assert "severity_score" not in f.extra, (
                f"Expected no severity_score when enrich=False, got: {f.extra}"
            )

    def test_enrich_true_attaches_severity_score(self, fake_extracted_tree):
        """When enrich=True, binary findings get a severity_score extra field."""
        _ensure_binary_stubs()
        from embalmer.pipeline import run
        from embalmer.models import ExtractionResult, Finding

        _reset_kev_cache()

        mock_score = SeverityScore(cvss=7.5, epss=0.04, in_kev=False, label="high",
                                   cve_id="CVE-2020-0001")

        fake_result = ExtractionResult(
            extraction_tree={},
            file_count=2,
            extraction_time_ms=1,
            extract_root=str(fake_extracted_tree / "sample-firmware.bin_extract"),
        )

        sample_findings = [
            Finding(category="binary", path="bin/busybox", type="CWE-120",
                    detail="overflow", severity="info"),
        ]

        with patch("embalmer.pipeline.extract.extract", return_value=fake_result), \
             patch("embalmer.pipeline.binaries.analyze", return_value=sample_findings), \
             patch("embalmer.pipeline.score_cwe", return_value=mock_score):
            report = run(
                firmware="fake.bin",
                workdir="/tmp",
                checks="binaries",
                enrich=True,
            )

        assert report.binaries is not None
        enriched = [f for f in report.binaries if "severity_score" in f.extra]
        assert enriched, "Expected at least one finding with severity_score"
        for f in enriched:
            assert f.extra["severity_score"]["label"] == "high"
            assert f.severity == "high"


# ---------------------------------------------------------------------------
# CLI --no-enrich flag
# ---------------------------------------------------------------------------


class TestCliNoEnrichFlag:
    def setup_method(self):
        _ensure_binary_stubs()

    def test_no_enrich_flag_parsed(self):
        from embalmer.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["--firmware", "x.bin", "--no-enrich"])
        assert args.no_enrich is True

    def test_enrich_default_is_false(self):
        from embalmer.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["--firmware", "x.bin"])
        assert args.no_enrich is False
