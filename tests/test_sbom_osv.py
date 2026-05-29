"""Tests for OSV.dev cross-referencing of package-database SBOM components.

The package-DB companion to :mod:`tests.test_sbom_cve` — exercises
:mod:`embalmer.sbom_osv`, which resolves ``dpkg``/``opkg``/``apk`` SBOM
components against OSV.dev (the canonical purl-keyed public vuln database)
and merges the matches into the same ``SbomCveReport`` shape the NVD
cross-reference produces, so the report's ``sbom.vulnerabilities`` section is
the union of both upstreams.

All HTTP is mocked — no real network. OSV's POST endpoint is mocked through a
patch on :func:`urllib.request.urlopen`; KEV reuses
:func:`embalmer.severity._fetch_json`'s cache and is patched the same way as
the existing NVD tests.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from embalmer import sbom_osv
from embalmer.models import Finding
from embalmer.sbom import Component, Sbom
from embalmer.sbom_cve import CveMatch, SbomCveReport
from embalmer.sbom_osv import cross_reference
from embalmer.severity import _reset_kev_cache


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Force each test to use a fresh, empty embalmer cache directory.

    OSV responses (and EPSS / NVD payloads) are cached to disk under
    ``$EMBALMER_CACHE_DIR`` for 24h; without isolation a payload mocked into
    one test would survive into the next and shadow its mock. Reimport-resets
    the resolved cache dir on :mod:`embalmer.severity` for the duration of
    each test.
    """
    import embalmer.severity as sev

    cache = tmp_path / "embalmer-cache"
    monkeypatch.setattr(sev, "_CACHE_DIR", cache)
    yield


# ---------------------------------------------------------------------------
# OSV / KEV payload builders (api.osv.dev v1/query shape)
# ---------------------------------------------------------------------------


def _osv_vuln(
    osv_id: str,
    aliases: list[str] | None = None,
    cvss: float | None = None,
    summary: str = "",
) -> dict:
    """One OSV vulnerability record matching the api.osv.dev v1/query shape."""
    record: dict = {"id": osv_id}
    if aliases is not None:
        record["aliases"] = aliases
    if summary:
        record["summary"] = summary
    if cvss is not None:
        # OSV records carry severity as a list of typed scores; the easiest path
        # to a numeric base score is the ``database_specific.cvss.score`` field
        # many feeds carry (Debian, GHSA, etc.).
        record["database_specific"] = {"cvss": {"score": cvss}}
    return record


def _osv_response(vulns: list[dict]) -> dict:
    return {"vulns": vulns}


def _kev_response(cve_ids: list[str]) -> dict:
    return {"vulnerabilities": [{"cveID": c} for c in cve_ids]}


def _mock_urlopen(payload: dict):
    """A patched ``urlopen`` that returns a single canned JSON body."""

    class _Resp:
        def __init__(self, body: bytes):
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    body = json.dumps(payload).encode("utf-8")
    return lambda req, timeout=10: _Resp(body)


def _mock_urlopen_per_purl(per_purl: dict[str, dict], default: dict | None = None):
    """A urlopen patch that varies the OSV response per purl POST body.

    The body of the OSV request carries the queried purl; this picks the
    response by substring match against the request body so multi-component
    tests can give each component a different OSV response.
    """

    class _Resp:
        def __init__(self, body: bytes):
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _side(req, timeout=10):
        # urllib.request.Request stores the POST body on ``.data``.
        raw = (req.data or b"").decode("utf-8", errors="replace")
        for purl, resp in per_purl.items():
            if purl in raw:
                return _Resp(json.dumps(resp).encode("utf-8"))
        return _Resp(json.dumps(default or {"vulns": []}).encode("utf-8"))

    return _side


def _mock_fetch(url_map: dict):
    """Reused from test_sbom_cve: a side_effect for _fetch_json (KEV/EPSS)."""

    def _side(url, timeout=10):
        for key, val in url_map.items():
            if key in url:
                return val
        return None

    return _side


def _dpkg_bash() -> Component:
    """A dpkg package component (purl-only, no CPE — the OSV subject)."""
    return Component(
        name="bash",
        version="5.0-4",
        source="dpkg",
        architecture="amd64",
        db_path="var/lib/dpkg/status",
    )


def _apk_busybox() -> Component:
    return Component(
        name="busybox",
        version="1.35.0-r0",
        source="apk",
        db_path="lib/apk/db/installed",
    )


def _opkg_dropbear() -> Component:
    return Component(
        name="dropbear",
        version="2019.78-1",
        source="opkg",
        db_path="var/lib/opkg/status",
    )


def _openssl_binary() -> Component:
    """A binary-detected component (CPE-bearing) — must be SKIPPED by OSV."""
    return Component(
        name="openssl",
        version="1.0.1f",
        source="binary",
        db_path="usr/lib/libcrypto.so",
        cpe="cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        supplier="openssl",
    )


# ---------------------------------------------------------------------------
# Pure helpers (no I/O)
# ---------------------------------------------------------------------------


class TestExtractOsvCvss:
    def test_pulls_score_from_database_specific(self):
        rec = _osv_vuln("OSV-1", aliases=["CVE-2020-0001"], cvss=7.5)
        assert sbom_osv._extract_osv_cvss(rec) == 7.5

    def test_takes_max_across_severity_entries(self):
        rec = {
            "severity": [
                {"type": "CVSS_V3", "score": "5.0"},
                {"type": "CVSS_V3", "score": "8.1"},
            ],
        }
        assert sbom_osv._extract_osv_cvss(rec) == 8.1

    def test_none_when_no_score_present(self):
        assert sbom_osv._extract_osv_cvss({"id": "OSV-X"}) is None

    def test_numeric_score_in_severity_entry(self):
        rec = {"severity": [{"type": "CVSS_V3", "score": 9.8}]}
        assert sbom_osv._extract_osv_cvss(rec) == 9.8


class TestCveIds:
    def test_returns_cve_aliases_only(self):
        # OSV ids (GHSA-, DSA-) are not CVEs and must be filtered out.
        rec = {
            "id": "GHSA-xxxx",
            "aliases": ["CVE-2020-0001", "DSA-1234-1", "CVE-2020-0002"],
        }
        assert sbom_osv._cve_ids(rec) == ["CVE-2020-0001", "CVE-2020-0002"]

    def test_returns_cve_when_id_itself_is_a_cve(self):
        rec = {"id": "CVE-2020-9999"}
        assert sbom_osv._cve_ids(rec) == ["CVE-2020-9999"]

    def test_dedups_id_and_aliases(self):
        rec = {"id": "CVE-2020-0001", "aliases": ["CVE-2020-0001", "CVE-2020-0002"]}
        assert sbom_osv._cve_ids(rec) == ["CVE-2020-0001", "CVE-2020-0002"]

    def test_empty_when_no_cve_ids(self):
        assert sbom_osv._cve_ids({"id": "GHSA-abc", "aliases": ["DSA-1"]}) == []


class TestSummary:
    def test_prefers_summary(self):
        rec = {"summary": "Heartbleed.", "details": "Long details..."}
        assert sbom_osv._summary(rec) == "Heartbleed."

    def test_falls_back_to_details_first_line(self):
        rec = {"details": "First line\nSecond line"}
        assert sbom_osv._summary(rec) == "First line"

    def test_empty_when_neither_present(self):
        assert sbom_osv._summary({}) == ""


# ---------------------------------------------------------------------------
# cross_reference (network mocked)
# ---------------------------------------------------------------------------


class TestCrossReference:
    def setup_method(self):
        _reset_kev_cache()

    def test_resolves_dpkg_component_to_its_cves(self):
        comp = _dpkg_bash()
        osv = _osv_response(
            [
                _osv_vuln(
                    "OSV-2019-0001",
                    aliases=["CVE-2019-18276"],
                    cvss=7.8,
                    summary="bash setuid drop",
                ),
                _osv_vuln(
                    "OSV-2014-0001",
                    aliases=["CVE-2014-6271"],
                    cvss=10.0,
                    summary="Shellshock",
                ),
            ]
        )

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch(
            "urllib.request.urlopen", side_effect=_mock_urlopen(osv)
        ):
            report = cross_reference(Sbom(components=[comp]))

        assert report.components_checked == 1
        assert report.components_with_cves == 1
        assert report.cve_count == 2
        ids = [m.cve_id for m in report.matches]
        # Worst-CVSS-first ordering: 10.0 before 7.8.
        assert ids == ["CVE-2014-6271", "CVE-2019-18276"]
        # Severity ladder identical to the NVD path: 10.0 -> critical, 7.8 -> high.
        assert report.matches[0].severity == "critical"
        assert report.matches[1].severity == "high"
        assert report.matches[0].purl == comp.purl()
        assert report.matches[0].description == "Shellshock"
        assert report.sources == ("OSV",)

    def test_resolves_apk_and_opkg_components(self):
        apk = _apk_busybox()
        opkg = _opkg_dropbear()
        per_purl = {
            apk.purl(): _osv_response(
                [_osv_vuln("OSV-APK-1", aliases=["CVE-2022-0001"], cvss=6.5)]
            ),
            opkg.purl(): _osv_response(
                [_osv_vuln("OSV-OPKG-1", aliases=["CVE-2023-0001"], cvss=8.0)]
            ),
        }

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch(
            "urllib.request.urlopen",
            side_effect=_mock_urlopen_per_purl(per_purl),
        ):
            report = cross_reference(Sbom(components=[apk, opkg]))

        assert report.components_checked == 2
        assert report.components_with_cves == 2
        purls = {m.purl for m in report.matches}
        assert apk.purl() in purls
        assert opkg.purl() in purls

    def test_binary_detected_component_is_skipped(self):
        # A binary-detected (CPE-bearing) component is the NVD path's territory;
        # OSV must skip it so the two paths don't double-cover the same component.
        comp = _openssl_binary()
        osv = _osv_response(
            [_osv_vuln("OSV-X", aliases=["CVE-9999-0001"], cvss=9.0)]
        )

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch(
            "urllib.request.urlopen", side_effect=_mock_urlopen(osv)
        ) as urlopen:
            report = cross_reference(Sbom(components=[comp]))

        assert report.components_checked == 0
        assert report.cve_count == 0
        # No eligible component -> OSV is never even queried.
        urlopen.assert_not_called()

    def test_kev_membership_pins_critical(self):
        comp = _dpkg_bash()
        osv = _osv_response(
            [_osv_vuln("OSV-1", aliases=["CVE-2014-6271"], cvss=4.0)]
        )

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch(
                {"cisa.gov": _kev_response(["CVE-2014-6271"])}
            ),
        ), patch(
            "urllib.request.urlopen", side_effect=_mock_urlopen(osv)
        ):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == 1
        m = report.matches[0]
        assert m.in_kev is True
        # KEV pins to critical regardless of the 4.0 CVSS.
        assert m.severity == "critical"

    def test_offline_returns_empty_without_raising(self):
        comp = _dpkg_bash()

        def _raise(req, timeout=10):
            raise OSError("network down")

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch("urllib.request.urlopen", side_effect=_raise):
            report = cross_reference(Sbom(components=[comp]))

        # Component was eligible but OSV failed -> graceful empty.
        assert report.components_checked == 1
        assert report.cve_count == 0
        assert report.components_with_cves == 0

    def test_empty_sbom_is_vacuously_empty(self):
        with patch("urllib.request.urlopen") as urlopen:
            report = cross_reference(Sbom(components=[]))
        assert report.components_checked == 0
        assert report.cve_count == 0
        urlopen.assert_not_called()

    def test_only_cve_aliases_are_recorded(self):
        # An OSV record with a non-CVE id and no CVE aliases must yield no matches
        # — the cross-reference surfaces CVEs, not distro-specific advisories.
        comp = _dpkg_bash()
        osv = _osv_response([_osv_vuln("DSA-1234-1", aliases=["DLA-5678-1"], cvss=7.0)])

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch("urllib.request.urlopen", side_effect=_mock_urlopen(osv)):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == 0
        assert report.components_with_cves == 0

    def test_cap_keeps_worst_cvss_first(self):
        # Generate 30 OSV records with varying CVSS; the cap (_MAX_CVES_PER_COMPONENT)
        # must keep the 25 highest-severity ones in worst-first order.
        comp = _dpkg_bash()
        vulns = [
            _osv_vuln(
                f"OSV-{i:03d}",
                aliases=[f"CVE-2024-{i:04d}"],
                cvss=float(i) / 3.0,
            )
            for i in range(1, 31)
        ]
        osv = _osv_response(vulns)

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch("urllib.request.urlopen", side_effect=_mock_urlopen(osv)):
            report = cross_reference(Sbom(components=[comp]))

        assert report.cve_count == sbom_osv._MAX_CVES_PER_COMPONENT
        # First entry must be the highest-CVSS one (i=30 -> CVSS 10.0).
        assert report.matches[0].cve_id == "CVE-2024-0030"


# ---------------------------------------------------------------------------
# Merge into an existing NVD report (the unified sbom.vulnerabilities path)
# ---------------------------------------------------------------------------


class TestMergeWithExistingNvdReport:
    def setup_method(self):
        _reset_kev_cache()

    def test_osv_matches_are_appended_to_existing_report(self):
        comp = _dpkg_bash()
        existing = SbomCveReport(
            matches=[
                CveMatch(
                    cve_id="CVE-2014-0160",
                    purl="pkg:generic/openssl@1.0.1f",
                    cvss=7.5,
                    severity="high",
                )
            ],
            components_checked=1,
        )
        osv = _osv_response(
            [_osv_vuln("OSV-1", aliases=["CVE-2014-6271"], cvss=10.0)]
        )

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch("urllib.request.urlopen", side_effect=_mock_urlopen(osv)):
            merged = cross_reference(Sbom(components=[comp]), existing=existing)

        assert merged is existing  # merged in-place
        # NVD entry preserved + OSV entry appended.
        ids = [m.cve_id for m in merged.matches]
        assert "CVE-2014-0160" in ids
        assert "CVE-2014-6271" in ids
        # Both upstreams credited.
        assert merged.sources == ("NVD", "OSV")
        # Components checked is the sum (1 from NVD + 1 from OSV).
        assert merged.components_checked == 2

    def test_dedup_by_cve_id_and_purl(self):
        # An NVD entry and an OSV entry that happen to assert the same CVE on
        # the same purl must surface ONCE in the merged report.
        comp = _dpkg_bash()
        purl = comp.purl()
        existing = SbomCveReport(
            matches=[
                CveMatch(
                    cve_id="CVE-2019-18276",
                    purl=purl,
                    cvss=7.8,
                    severity="high",
                )
            ],
            components_checked=0,
        )
        osv = _osv_response(
            [_osv_vuln("OSV-1", aliases=["CVE-2019-18276"], cvss=7.8)]
        )

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch("urllib.request.urlopen", side_effect=_mock_urlopen(osv)):
            merged = cross_reference(Sbom(components=[comp]), existing=existing)

        # Just the one entry, not duplicated.
        assert merged.cve_count == 1
        assert merged.matches[0].cve_id == "CVE-2019-18276"

    def test_source_label_reflects_only_osv_when_no_nvd_run(self):
        comp = _dpkg_bash()
        osv = _osv_response(
            [_osv_vuln("OSV-1", aliases=["CVE-2014-6271"], cvss=10.0)]
        )

        with patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch("urllib.request.urlopen", side_effect=_mock_urlopen(osv)):
            report = cross_reference(Sbom(components=[comp]))

        d = report.to_dict()
        # OSV-only run names just OSV as the source.
        assert "OSV.dev" in d["source"]
        assert "NVD" not in d["source"]

    def test_source_label_is_unchanged_for_nvd_only_report(self):
        # Backwards-compat guarantee: a SbomCveReport that ran only NVD (no OSV
        # merge) must emit the exact historical ``source`` string so every prior
        # consumer reads byte-for-byte the same payload.
        rep = SbomCveReport(matches=[], components_checked=0)
        assert (
            rep.to_dict()["source"]
            == "NVD (services.nvd.nist.gov, CPE-name cross-reference)"
        )


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


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

    def test_sbom_osv_check_attaches_vulnerabilities(self, tmp_path):
        # A dpkg-sourced SBOM component (no CPE) drives the OSV lookup end-to-end.
        bash = _dpkg_bash()
        sbom_obj = Sbom(components=[bash])
        osv = _osv_response(
            [_osv_vuln("OSV-1", aliases=["CVE-2014-6271"], cvss=10.0, summary="Shellshock")]
        )

        from embalmer import pipeline

        extract_root = tmp_path / "ex"
        extract_root.mkdir()
        with patch(
            "embalmer.pipeline.extract.extract",
            return_value=self._fake_extract(extract_root),
        ), patch(
            "embalmer.pipeline.components.scan", return_value=[]
        ), patch(
            "embalmer.pipeline.sbom.scan", return_value=sbom_obj
        ), patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch({"cisa.gov": _kev_response([])}),
        ), patch(
            "urllib.request.urlopen", side_effect=_mock_urlopen(osv)
        ):
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                sbom_osv_check=True,
                _blight_analyzer=lambda *a, **k: [],
            )

        data = report.to_dict()
        assert "vulnerabilities" in data["sbom"]
        cve = data["sbom"]["vulnerabilities"]
        assert cve["cve_count"] == 1
        assert cve["vulnerabilities"][0]["cve_id"] == "CVE-2014-6271"
        # OSV-only source label.
        assert "OSV.dev" in cve["source"]

    def test_sbom_cve_and_sbom_osv_together_produce_unified_section(self, tmp_path):
        # The flagship use case: --sbom-cve + --sbom-osv resolves every
        # SBOM component (CPE-bearing via NVD, package-DB via OSV) into one
        # unified `sbom.vulnerabilities` array.
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
        bash = _dpkg_bash()
        sbom_obj = Sbom(components=[bash])

        # NVD answers for the CPE (Heartbleed); OSV answers for the dpkg purl
        # (Shellshock).
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2014-0160",
                        "descriptions": [{"lang": "en", "value": "Heartbleed."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 7.5, "version": "3.1"}}
                            ]
                        },
                    }
                }
            ],
            "totalResults": 1,
        }
        osv = _osv_response(
            [_osv_vuln("OSV-1", aliases=["CVE-2014-6271"], cvss=10.0)]
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
            "embalmer.pipeline.sbom.scan", return_value=sbom_obj
        ), patch(
            "embalmer.severity._fetch_json",
            side_effect=_mock_fetch(
                {"nvd.nist.gov": nvd, "cisa.gov": _kev_response([])}
            ),
        ), patch(
            "urllib.request.urlopen", side_effect=_mock_urlopen(osv)
        ):
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                sbom_cve_check=True,
                sbom_osv_check=True,
                _blight_analyzer=lambda *a, **k: [],
            )

        data = report.to_dict()
        cve = data["sbom"]["vulnerabilities"]
        ids = [v["cve_id"] for v in cve["vulnerabilities"]]
        # Both upstreams' findings present in one unified section.
        assert "CVE-2014-0160" in ids  # NVD via CPE
        assert "CVE-2014-6271" in ids  # OSV via purl
        # Source string credits both upstreams.
        assert "NVD" in cve["source"]
        assert "OSV.dev" in cve["source"]

    def test_no_enrich_skips_osv_cross_reference(self, tmp_path):
        bash = _dpkg_bash()
        sbom_obj = Sbom(components=[bash])

        from embalmer import pipeline

        extract_root = tmp_path / "ex"
        extract_root.mkdir()
        with patch(
            "embalmer.pipeline.extract.extract",
            return_value=self._fake_extract(extract_root),
        ), patch(
            "embalmer.pipeline.components.scan", return_value=[]
        ), patch(
            "embalmer.pipeline.sbom.scan", return_value=sbom_obj
        ), patch(
            "urllib.request.urlopen"
        ) as urlopen, patch(
            "embalmer.severity._fetch_json"
        ) as fetch:
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                sbom_osv_check=True,
                enrich=False,
                _blight_analyzer=lambda *a, **k: [],
            )

        # Air-gapped: no cross-reference attached, no OSV nor KEV/EPSS queried.
        assert report.sbom_cve is None
        urlopen.assert_not_called()
        fetch.assert_not_called()

    def test_default_run_does_not_query_osv(self, tmp_path):
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
            "urllib.request.urlopen"
        ) as urlopen:
            report = pipeline.run(
                firmware="fw.bin",
                workdir=str(tmp_path / "work"),
                checks="all",
                _blight_analyzer=lambda *a, **k: [],
            )
        assert report.sbom_cve is None
        urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# CLI flag wiring
# ---------------------------------------------------------------------------


class TestCliFlag:
    def test_sbom_osv_flag_is_recognized(self):
        from embalmer.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["--firmware", "x.bin", "--sbom-osv"])
        assert args.sbom_osv_check is True

    def test_default_off(self):
        from embalmer.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["--firmware", "x.bin"])
        assert args.sbom_osv_check is False
