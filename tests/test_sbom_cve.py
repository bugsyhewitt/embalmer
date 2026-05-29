"""Tests for NVD CVE cross-referencing of SBOM components.

All HTTP calls are mocked — no real network access is made. The cross-reference
reuses :mod:`embalmer.severity`'s cached, timeout-guarded NVD/KEV client, so the
mocking convention mirrors ``tests/test_severity.py``: patch
``embalmer.severity._fetch_json`` with a URL-substring lookup, and reset the
process-level KEV cache between tests.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from embalmer import sbom_cve
from embalmer.models import Finding
from embalmer.sbom import Component, Sbom
from embalmer.sbom_cve import CveMatch, SbomCveReport, cross_reference
from embalmer.severity import _reset_kev_cache


# ---------------------------------------------------------------------------
# Fake NVD / KEV payload builders (NVD API v2 shape)
# ---------------------------------------------------------------------------


def _nvd_cve_item(cve_id: str, cvss: float | None, desc: str = "") -> dict:
    item: dict = {"id": cve_id}
    if desc:
        item["descriptions"] = [{"lang": "en", "value": desc}]
    if cvss is not None:
        item["metrics"] = {
            "cvssMetricV31": [{"cvssData": {"baseScore": cvss, "version": "3.1"}}]
        }
    return item


def _nvd_response(items: list[dict]) -> dict:
    return {
        "vulnerabilities": [{"cve": i} for i in items],
        "totalResults": len(items),
    }


def _kev_response(cve_ids: list[str]) -> dict:
    return {"vulnerabilities": [{"cveID": c} for c in cve_ids]}


def _epss_response(cve_id: str, score: float) -> dict:
    """A FIRST.org EPSS API response for one CVE (the shape _get_epss reads)."""
    return {"data": [{"cve": cve_id, "epss": str(score)}]}


def _mock_fetch_epss(url_map: dict, epss_map: dict[str, float]):
    """side_effect like _mock_fetch but also answers FIRST.org EPSS lookups.

    EPSS URLs carry the CVE id as a query param (``?cve=CVE-...``); resolve by
    matching the CVE id present in the URL against ``epss_map``.
    """

    def _side(url, timeout=10):
        if "first.org" in url:
            for cve_id, score in epss_map.items():
                if cve_id in url:
                    return _epss_response(cve_id, score)
            return None
        for key, val in url_map.items():
            if key in url:
                return val
        return None

    return _side


def _mock_fetch(url_map: dict):
    """side_effect for _fetch_json: return the value whose key is in the URL."""

    def _side(url, timeout=10):
        for key, val in url_map.items():
            if key in url:
                return val
        return None

    return _side


def _openssl_component() -> Component:
    """A binary-detected component carrying a CPE (the cross-reference subject)."""
    return Component(
        name="openssl",
        version="1.0.1f",
        source="binary",
        db_path="usr/lib/libcrypto.so",
        cpe="cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        supplier="openssl",
    )


def _dpkg_component() -> Component:
    """A package-database component — purl only, NO cpe (must be skipped)."""
    return Component(
        name="bash",
        version="5.0-4",
        source="dpkg",
        architecture="amd64",
        db_path="var/lib/dpkg/status",
    )


# ---------------------------------------------------------------------------
# CveMatch unit tests (no I/O)
# ---------------------------------------------------------------------------


class TestCveMatchRender:
    def test_to_cyclonedx_carries_id_source_rating_kev_and_affects(self):
        m = CveMatch(
            cve_id="CVE-2014-0160",
            purl="pkg:generic/openssl@1.0.1f",
            cvss=7.5,
            severity="high",
            in_kev=True,
            description="Heartbleed.",
        )
        out = m.to_cyclonedx()
        assert out["id"] == "CVE-2014-0160"
        assert out["source"]["name"] == "NVD"
        assert "nvd.nist.gov/vuln/detail/CVE-2014-0160" in out["source"]["url"]
        assert out["description"] == "Heartbleed."
        assert out["ratings"][0]["score"] == 7.5
        assert out["ratings"][0]["severity"] == "high"
        # KEV is a property, not a rating.
        props = {p["name"]: p["value"] for p in out["properties"]}
        assert props["embalmer:in-kev"] == "true"
        # affects links the CVE back to the component by purl.
        assert out["affects"] == [{"ref": "pkg:generic/openssl@1.0.1f"}]

    def test_to_cyclonedx_omits_rating_without_cvss(self):
        m = CveMatch(cve_id="CVE-2020-0001", purl="pkg:generic/x@1.0", cvss=None)
        out = m.to_cyclonedx()
        assert "ratings" not in out
        props = {p["name"]: p["value"] for p in out["properties"]}
        assert props["embalmer:in-kev"] == "false"

    def test_to_dict_quick_look_shape(self):
        m = CveMatch(
            cve_id="CVE-2014-0160",
            purl="pkg:generic/openssl@1.0.1f",
            cvss=7.5,
            severity="high",
            in_kev=False,
        )
        # No EPSS set -> the prior (pre-EPSS) quick-look shape is unchanged.
        assert m.to_dict() == {
            "cve_id": "CVE-2014-0160",
            "purl": "pkg:generic/openssl@1.0.1f",
            "cvss": 7.5,
            "severity": "high",
            "in_kev": False,
        }

    def test_to_dict_surfaces_epss_when_present(self):
        m = CveMatch(
            cve_id="CVE-2014-0160",
            purl="pkg:generic/openssl@1.0.1f",
            cvss=6.0,
            severity="high",
            in_kev=False,
            epss=0.9,
            epss_promoted=True,
        )
        d = m.to_dict()
        assert d["epss"] == 0.9
        assert d["epss_promoted"] is True

    def test_to_cyclonedx_carries_epss_property_and_promotion_flag(self):
        m = CveMatch(
            cve_id="CVE-2014-0160",
            purl="pkg:generic/openssl@1.0.1f",
            cvss=6.0,
            severity="high",
            in_kev=False,
            epss=0.87,
            epss_promoted=True,
        )
        props = {p["name"]: p["value"] for p in m.to_cyclonedx()["properties"]}
        assert props["embalmer:epss"] == "0.87"
        assert props["embalmer:epss-promoted"] == "true"
        # The CVSS rating still reflects the promoted severity label.
        assert m.to_cyclonedx()["ratings"][0]["severity"] == "high"

    def test_to_cyclonedx_omits_epss_property_when_absent(self):
        m = CveMatch(cve_id="CVE-2020-0001", purl="pkg:generic/x@1.0", cvss=5.0)
        props = {p["name"]: p["value"] for p in m.to_cyclonedx()["properties"]}
        assert "embalmer:epss" not in props
        assert "embalmer:epss-promoted" not in props


# ---------------------------------------------------------------------------
# cross_reference (network mocked)
# ---------------------------------------------------------------------------


class TestCrossReference:
    def setup_method(self):
        _reset_kev_cache()

    def test_resolves_cpe_component_to_its_cves(self):
        comp = _openssl_component()
        nvd = _nvd_response(
            [
                _nvd_cve_item("CVE-2014-0160", 7.5, "Heartbleed."),
                _nvd_cve_item("CVE-2014-0224", 5.8, "CCS injection."),
            ]
        )
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = cross_reference(Sbom(components=[comp]))

        assert report.components_checked == 1
        assert report.components_with_cves == 1
        assert report.cve_count == 2
        ids = [m.cve_id for m in report.matches]
        # Worst-CVSS-first ordering: 7.5 before 5.8.
        assert ids == ["CVE-2014-0160", "CVE-2014-0224"]
        assert report.matches[0].cvss == 7.5
        assert report.matches[0].severity == "high"
        assert report.matches[0].purl == comp.purl()

    def test_cvss_v40_only_cve_is_scored(self):
        """A CVE NVD scores only under CVSS v4.0 must still resolve a CVSS-based
        severity in the SBOM cross-reference (not fall through to info)."""
        comp = _openssl_component()
        # Build a CVE item carrying ONLY a cvssMetricV40 block.
        v40_item = {
            "id": "CVE-2024-41592",
            "descriptions": [{"lang": "en", "value": "DrayTek overflow."}],
            "metrics": {
                "cvssMetricV40": [
                    {"cvssData": {"baseScore": 9.3, "version": "4.0"}}
                ]
            },
        }
        nvd = _nvd_response([v40_item])
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == 1
        m = report.matches[0]
        assert m.cve_id == "CVE-2024-41592"
        assert m.cvss == 9.3
        assert m.severity == "critical"  # 9.3 >= 9.0

    def test_kev_membership_is_recorded_and_pins_critical(self):
        comp = _openssl_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 7.5)])
        fetch_map = {
            "nvd.nist.gov": nvd,
            "cisa.gov": _kev_response(["CVE-2014-0160"]),
        }
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == 1
        m = report.matches[0]
        assert m.in_kev is True
        # KEV pins to critical regardless of the 7.5 CVSS (reuses severity logic).
        assert m.severity == "critical"

    def test_package_db_component_without_cpe_is_skipped(self):
        # A dpkg component has a purl but no CPE; NVD matches on CPE, so it must
        # not be cross-referenced (no overclaiming).
        comp = _dpkg_component()
        fetch_map = {
            "nvd.nist.gov": _nvd_response([_nvd_cve_item("CVE-9999-0001", 9.0)]),
            "cisa.gov": _kev_response([]),
        }
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ) as fetch:
            report = cross_reference(Sbom(components=[comp]))

        assert report.components_checked == 0
        assert report.cve_count == 0
        # No CPE-bearing component -> NVD is never even queried.
        fetch.assert_not_called()

    def test_only_cpe_components_are_checked_in_a_mixed_sbom(self):
        cpe_comp = _openssl_component()
        db_comp = _dpkg_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 7.5)])
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = cross_reference(Sbom(components=[cpe_comp, db_comp]))

        assert report.components_checked == 1
        assert report.cve_count == 1
        assert report.matches[0].purl == cpe_comp.purl()

    def test_offline_returns_empty_report_without_raising(self):
        comp = _openssl_component()
        with patch("embalmer.severity._fetch_json", return_value=None):
            report = cross_reference(Sbom(components=[comp]))

        # Component was eligible but NVD returned nothing -> graceful empty.
        assert report.components_checked == 1
        assert report.cve_count == 0
        assert report.components_with_cves == 0

    def test_empty_sbom_is_vacuously_empty(self):
        with patch("embalmer.severity._fetch_json") as fetch:
            report = cross_reference(Sbom(components=[]))
        assert report.components_checked == 0
        assert report.cve_count == 0
        fetch.assert_not_called()

    def test_cves_are_capped_and_worst_severity_kept(self):
        comp = _openssl_component()
        # 30 CVEs; only the 25 worst should survive the cap.
        items = [
            _nvd_cve_item(f"CVE-2020-{1000 + i}", float(i % 10)) for i in range(30)
        ]
        # Add one guaranteed-top-severity CVE.
        items.append(_nvd_cve_item("CVE-2020-9999", 10.0))
        nvd = _nvd_response(items)
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == sbom_cve._MAX_CVES_PER_COMPONENT
        # The 10.0 CVE must survive the cap (worst-first sort).
        assert report.matches[0].cve_id == "CVE-2020-9999"
        assert report.matches[0].cvss == 10.0

    def test_epss_enriches_match_and_promotes_severity(self):
        # A CVSS of 6.0 is "medium"; a high EPSS (>= default 0.5) promotes it to
        # "high" — the same multi-factor triage the binary-finding path applies.
        comp = _openssl_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 6.0)])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])},
            {"CVE-2014-0160": 0.9},
        )
        with patch("embalmer.severity._fetch_json", side_effect=fetch):
            report = cross_reference(Sbom(components=[comp]))

        m = report.matches[0]
        assert m.epss == 0.9
        assert m.severity == "high"  # promoted from base "medium"
        assert m.epss_promoted is True

    def test_low_epss_does_not_promote(self):
        comp = _openssl_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 6.0)])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])},
            {"CVE-2014-0160": 0.01},
        )
        with patch("embalmer.severity._fetch_json", side_effect=fetch):
            report = cross_reference(Sbom(components=[comp]))

        m = report.matches[0]
        assert m.epss == 0.01
        assert m.severity == "medium"  # unchanged from CVSS base
        assert m.epss_promoted is False

    def test_epss_threshold_override_disables_promotion(self):
        comp = _openssl_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 6.0)])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])},
            {"CVE-2014-0160": 0.9},
        )
        # A threshold above 1.0 makes promotion unreachable (EPSS is 0.0-1.0).
        with patch("embalmer.severity._fetch_json", side_effect=fetch):
            report = cross_reference(Sbom(components=[comp]), epss_threshold=1.1)

        m = report.matches[0]
        assert m.epss == 0.9
        assert m.severity == "medium"
        assert m.epss_promoted is False

    def test_missing_epss_falls_back_to_cvss_label(self):
        # EPSS lookup returns nothing -> no crash, no promotion, epss stays None.
        comp = _openssl_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 6.0)])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])},
            {},  # no EPSS for any CVE
        )
        with patch("embalmer.severity._fetch_json", side_effect=fetch):
            report = cross_reference(Sbom(components=[comp]))

        m = report.matches[0]
        assert m.epss is None
        assert m.severity == "medium"
        assert m.epss_promoted is False

    def test_kev_critical_is_not_epss_promoted_further(self):
        # A KEV CVE is already critical; EPSS cannot push it higher.
        comp = _openssl_component()
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 7.5)])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response(["CVE-2014-0160"])},
            {"CVE-2014-0160": 0.99},
        )
        with patch("embalmer.severity._fetch_json", side_effect=fetch):
            report = cross_reference(Sbom(components=[comp]))

        m = report.matches[0]
        assert m.severity == "critical"
        assert m.epss_promoted is False

    def test_epss_fetched_only_for_capped_cves(self):
        # EPSS lookups must run AFTER the per-component cap, so a widely-vulnerable
        # component never triggers more than _MAX_CVES_PER_COMPONENT EPSS calls.
        comp = _openssl_component()
        items = [_nvd_cve_item(f"CVE-2020-{1000 + i}", 6.0) for i in range(40)]
        nvd = _nvd_response(items)

        epss_calls: list[str] = []

        def _side(url, timeout=10):
            if "first.org" in url:
                epss_calls.append(url)
                return None
            if "nvd.nist.gov" in url:
                return nvd
            if "cisa.gov" in url:
                return _kev_response([])
            return None

        with patch("embalmer.severity._fetch_json", side_effect=_side):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == sbom_cve._MAX_CVES_PER_COMPONENT
        assert len(epss_calls) == sbom_cve._MAX_CVES_PER_COMPONENT

    def test_duplicate_cve_ids_are_collapsed(self):
        comp = _openssl_component()
        nvd = _nvd_response(
            [
                _nvd_cve_item("CVE-2014-0160", 7.5),
                _nvd_cve_item("CVE-2014-0160", 7.5),
            ]
        )
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        with patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = cross_reference(Sbom(components=[comp]))
        assert report.cve_count == 1


# ---------------------------------------------------------------------------
# SbomCveReport.to_dict
# ---------------------------------------------------------------------------


class TestReportToDict:
    def test_to_dict_carries_summary_and_cyclonedx_bom(self):
        report = SbomCveReport(
            matches=[
                CveMatch(
                    cve_id="CVE-2014-0160",
                    purl="pkg:generic/openssl@1.0.1f",
                    cvss=7.5,
                    severity="high",
                    in_kev=True,
                )
            ],
            components_checked=1,
        )
        d = report.to_dict()
        assert d["source"].startswith("NVD")
        assert d["components_checked"] == 1
        assert d["components_with_cves"] == 1
        assert d["cve_count"] == 1
        assert d["vulnerabilities"][0]["cve_id"] == "CVE-2014-0160"
        # The full CycloneDX vulnerabilities[] array rides under `bom`.
        assert d["bom"][0]["id"] == "CVE-2014-0160"
        assert d["bom"][0]["affects"] == [{"ref": "pkg:generic/openssl@1.0.1f"}]

    def test_empty_report_to_dict(self):
        d = SbomCveReport().to_dict()
        assert d["cve_count"] == 0
        assert d["vulnerabilities"] == []
        assert d["bom"] == []


# ---------------------------------------------------------------------------
# Pipeline integration (Article IX: exercise the real wiring)
# ---------------------------------------------------------------------------


def _write_apk_db(root, body: str) -> None:
    db = root / "lib" / "apk" / "db"
    db.mkdir(parents=True)
    (db / "installed").write_text(body, encoding="utf-8")


class TestPipelineIntegration:
    def setup_method(self):
        _reset_kev_cache()

    def _fake_extract(self, extract_root):
        from embalmer.models import ExtractionResult

        return ExtractionResult(
            extraction_tree={},
            file_count=0,
            extraction_time_ms=0,
            extract_root=str(extract_root),
            extractor_used="unblob",
        )

    def test_sbom_cve_check_attaches_vulnerabilities(self, tmp_path):
        # A binary-detected OpenSSL component (carries a CPE) drives the lookup.
        openssl_finding = Finding(
            category="component",
            path="usr/lib/libcrypto.so",
            type="openssl",
            detail="openssl 1.0.1f",
            severity="info",
            extra={
                "component": "openssl",
                "version": "1.0.1f",
                "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
                "vendor": "openssl",
            },
        )
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 7.5, "Heartbleed.")])
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}

        from embalmer import pipeline

        extract_root = tmp_path / "ex"
        extract_root.mkdir()
        with patch(
            "embalmer.pipeline.extract.extract",
            return_value=self._fake_extract(extract_root),
        ), patch(
            "embalmer.pipeline.components.scan", return_value=[openssl_finding]
        ), patch(
            "embalmer.pipeline.sbom.scan", return_value=Sbom(components=[])
        ), patch(
            "embalmer.severity._fetch_json", side_effect=_mock_fetch(fetch_map)
        ):
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                sbom_cve_check=True,
                _blight_analyzer=lambda *a, **k: [],
            )

        data = report.to_dict()
        assert "vulnerabilities" in data["sbom"]
        cve = data["sbom"]["vulnerabilities"]
        assert cve["cve_count"] == 1
        assert cve["vulnerabilities"][0]["cve_id"] == "CVE-2014-0160"
        assert cve["bom"][0]["affects"][0]["ref"].startswith("pkg:generic/openssl")

    def test_epss_threshold_flows_from_pipeline_to_cross_reference(self, tmp_path):
        # End-to-end: the pipeline's epss_threshold must reach the SBOM CVE
        # cross-reference so a high EPSS promotes the SBOM CVE's severity, the
        # same as it does for binary findings.
        openssl_finding = Finding(
            category="component",
            path="usr/lib/libcrypto.so",
            type="openssl",
            detail="openssl 1.0.1f",
            severity="info",
            extra={
                "component": "openssl",
                "version": "1.0.1f",
                "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
                "vendor": "openssl",
            },
        )
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 6.0, "Heartbleed.")])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])},
            {"CVE-2014-0160": 0.9},
        )

        from embalmer import pipeline

        extract_root = tmp_path / "ex"
        extract_root.mkdir()
        with patch(
            "embalmer.pipeline.extract.extract",
            return_value=self._fake_extract(extract_root),
        ), patch(
            "embalmer.pipeline.components.scan", return_value=[openssl_finding]
        ), patch(
            "embalmer.pipeline.sbom.scan", return_value=Sbom(components=[])
        ), patch(
            "embalmer.severity._fetch_json", side_effect=fetch
        ):
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                sbom_cve_check=True,
                _blight_analyzer=lambda *a, **k: [],
            )

        cve = report.to_dict()["sbom"]["vulnerabilities"]
        v = cve["vulnerabilities"][0]
        assert v["epss"] == 0.9
        assert v["severity"] == "high"
        assert v["epss_promoted"] is True

    def test_no_enrich_skips_cross_reference(self, tmp_path):
        openssl_finding = Finding(
            category="component",
            path="usr/lib/libcrypto.so",
            type="openssl",
            detail="openssl 1.0.1f",
            severity="info",
            extra={
                "component": "openssl",
                "version": "1.0.1f",
                "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
            },
        )
        from embalmer import pipeline

        extract_root = tmp_path / "ex"
        extract_root.mkdir()
        with patch(
            "embalmer.pipeline.extract.extract",
            return_value=self._fake_extract(extract_root),
        ), patch(
            "embalmer.pipeline.components.scan", return_value=[openssl_finding]
        ), patch(
            "embalmer.pipeline.sbom.scan", return_value=Sbom(components=[])
        ), patch(
            "embalmer.severity._fetch_json"
        ) as fetch:
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                sbom_cve_check=True,
                enrich=False,
                _blight_analyzer=lambda *a, **k: [],
            )

        # Air-gapped: no cross-reference attached, NVD never queried.
        assert report.sbom_cve is None
        assert "vulnerabilities" not in report.to_dict()["sbom"]
        fetch.assert_not_called()

    def test_default_run_does_not_cross_reference(self, tmp_path):
        from embalmer import pipeline

        extract_root = tmp_path / "ex"
        extract_root.mkdir()
        with patch(
            "embalmer.pipeline.extract.extract",
            return_value=self._fake_extract(extract_root),
        ), patch(
            "embalmer.pipeline.components.scan", return_value=[]
        ), patch(
            "embalmer.pipeline.sbom.scan", return_value=Sbom(components=[])
        ), patch(
            "embalmer.severity._fetch_json"
        ) as fetch:
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                _blight_analyzer=lambda *a, **k: [],
            )
        assert report.sbom_cve is None
        fetch.assert_not_called()


# ---------------------------------------------------------------------------
# CLI integration (end-to-end: real components check -> CPE -> NVD lookup)
# ---------------------------------------------------------------------------


class TestCliIntegration:
    def setup_method(self):
        _reset_kev_cache()

    def _plant_openssl_binary(self, root) -> None:
        """Plant an ELF-like file carrying a real OpenSSL version banner so the
        components check recovers a CPE-bearing component end-to-end."""
        base = root / "sample-firmware.bin_extract" / "usr" / "lib"
        base.mkdir(parents=True)
        (base / "libcrypto.so").write_bytes(
            b"\x7fELF\x02\x01\x01\x00" + b"OpenSSL 1.0.1f 6 Jan 2014\x00" + b"\x00" * 64
        )

    def test_cli_sbom_cve_json(self, sample_firmware, tmp_path, capsys, monkeypatch):
        import json as _json

        from embalmer import extract
        from embalmer.cli import main as cli_main

        monkeypatch.setattr(
            extract,
            "_run_unblob",
            lambda fw, wd: self._plant_openssl_binary(Path(wd)),
        )
        # Neutralize the real blight subprocess handoff — this test exercises the
        # components -> CPE -> NVD path, not binary analysis.
        monkeypatch.setattr("embalmer.binaries.analyze", lambda *a, **k: [])
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 7.5, "Heartbleed.")])
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        monkeypatch.setattr(
            "embalmer.severity._fetch_json", _mock_fetch(fetch_map)
        )

        rc = cli_main(
            [
                "--firmware",
                str(sample_firmware),
                "--workdir",
                str(tmp_path / "work"),
                "--checks",
                "all",
                "--sbom-cve",
                "--format",
                "json",
            ]
        )
        assert rc == 0
        data = _json.loads(capsys.readouterr().out)
        cve = data["sbom"]["vulnerabilities"]
        assert cve["cve_count"] == 1
        assert cve["vulnerabilities"][0]["cve_id"] == "CVE-2014-0160"
        assert cve["components_checked"] >= 1

    def test_cli_without_flag_omits_vulnerabilities(
        self, sample_firmware, tmp_path, capsys, monkeypatch
    ):
        import json as _json

        from embalmer import extract
        from embalmer.cli import main as cli_main

        monkeypatch.setattr(
            extract,
            "_run_unblob",
            lambda fw, wd: self._plant_openssl_binary(Path(wd)),
        )
        monkeypatch.setattr(
            "embalmer.severity._fetch_json", lambda *a, **k: None
        )
        rc = cli_main(
            [
                "--firmware",
                str(sample_firmware),
                "--workdir",
                str(tmp_path / "work"),
                "--checks",
                "sbom",
                "--format",
                "json",
            ]
        )
        assert rc == 0
        data = _json.loads(capsys.readouterr().out)
        assert "vulnerabilities" not in data["sbom"]

    def test_cli_sbom_cve_markdown(
        self, sample_firmware, tmp_path, capsys, monkeypatch
    ):
        from embalmer import extract
        from embalmer.cli import main as cli_main

        monkeypatch.setattr(
            extract,
            "_run_unblob",
            lambda fw, wd: self._plant_openssl_binary(Path(wd)),
        )
        monkeypatch.setattr("embalmer.binaries.analyze", lambda *a, **k: [])
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 7.5, "Heartbleed.")])
        fetch_map = {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
        monkeypatch.setattr(
            "embalmer.severity._fetch_json", _mock_fetch(fetch_map)
        )
        rc = cli_main(
            [
                "--firmware",
                str(sample_firmware),
                "--workdir",
                str(tmp_path / "work"),
                "--checks",
                "all",
                "--sbom-cve",
                "--format",
                "md",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "NVD CVE cross-reference" in out
        assert "CVE-2014-0160" in out
        # The cross-reference table now carries an EPSS column.
        assert "EPSS" in out

    def test_cli_sbom_cve_markdown_shows_epss_promotion(
        self, sample_firmware, tmp_path, capsys, monkeypatch
    ):
        from embalmer import extract
        from embalmer.cli import main as cli_main

        monkeypatch.setattr(
            extract,
            "_run_unblob",
            lambda fw, wd: self._plant_openssl_binary(Path(wd)),
        )
        monkeypatch.setattr("embalmer.binaries.analyze", lambda *a, **k: [])
        # A medium-CVSS CVE with a high EPSS -> promoted to high, flagged in the
        # markdown so the promotion is auditable from the report alone.
        nvd = _nvd_response([_nvd_cve_item("CVE-2014-0160", 6.0, "Heartbleed.")])
        fetch = _mock_fetch_epss(
            {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])},
            {"CVE-2014-0160": 0.9},
        )
        monkeypatch.setattr("embalmer.severity._fetch_json", fetch)
        rc = cli_main(
            [
                "--firmware",
                str(sample_firmware),
                "--workdir",
                str(tmp_path / "work"),
                "--checks",
                "all",
                "--sbom-cve",
                "--format",
                "md",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "high (EPSS)" in out
        assert "0.9" in out
