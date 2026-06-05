"""Tests for embalmer.sbom_age — SBOM component vulnerability-age check."""

from __future__ import annotations

import datetime
from unittest.mock import patch

import pytest

from embalmer.sbom_age import (
    DEFAULT_AGE_DAYS,
    RECENT_ACTIVITY_SEVERITY,
    AgedComponent,
    SbomAgeReport,
    _most_recent_modified,
    _parse_modified,
    check,
)


# ---------------------------------------------------------------------------
# _parse_modified
# ---------------------------------------------------------------------------

class TestParseModified:
    def test_valid_utc_z(self):
        dt = _parse_modified("2024-11-14T20:37:07Z")
        assert dt == datetime.datetime(2024, 11, 14, 20, 37, 7,
                                       tzinfo=datetime.timezone.utc)

    def test_valid_with_fractional(self):
        dt = _parse_modified("2024-11-14T20:37:07.123456Z")
        assert dt == datetime.datetime(2024, 11, 14, 20, 37, 7,
                                       tzinfo=datetime.timezone.utc)

    def test_none_input(self):
        assert _parse_modified(None) is None

    def test_not_a_string(self):
        assert _parse_modified(12345) is None

    def test_invalid_format(self):
        assert _parse_modified("not-a-date") is None

    def test_empty_string(self):
        assert _parse_modified("") is None


# ---------------------------------------------------------------------------
# _most_recent_modified
# ---------------------------------------------------------------------------

class TestMostRecentModified:
    def _make_record(self, modified, cve_id="CVE-2024-1234", aliases=None):
        rec = {"modified": modified, "id": cve_id}
        if aliases:
            rec["aliases"] = aliases
        return rec

    def test_single_record(self):
        records = [self._make_record("2024-06-01T00:00:00Z")]
        dt, cve = _most_recent_modified(records)
        assert dt == datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
        assert cve == "CVE-2024-1234"

    def test_picks_most_recent(self):
        records = [
            self._make_record("2024-03-01T00:00:00Z", "CVE-2024-0001"),
            self._make_record("2024-06-15T00:00:00Z", "CVE-2024-9999"),
            self._make_record("2024-01-01T00:00:00Z", "CVE-2024-0002"),
        ]
        dt, cve = _most_recent_modified(records)
        assert cve == "CVE-2024-9999"

    def test_empty_records(self):
        dt, cve = _most_recent_modified([])
        assert dt is None
        assert cve is None

    def test_no_modified_field(self):
        dt, cve = _most_recent_modified([{"id": "CVE-2024-0001"}])
        assert dt is None
        assert cve is None

    def test_cve_from_aliases(self):
        records = [{"modified": "2024-06-01T00:00:00Z", "id": "GHSA-xxxx",
                    "aliases": ["CVE-2024-9999"]}]
        dt, cve = _most_recent_modified(records)
        assert cve == "CVE-2024-9999"

    def test_non_dict_records_skipped(self):
        dt, cve = _most_recent_modified(["not-a-dict", None])
        assert dt is None


# ---------------------------------------------------------------------------
# AgedComponent
# ---------------------------------------------------------------------------

class TestAgedComponent:
    def test_recent_is_recently_active(self):
        c = AgedComponent(purl="pkg:deb/bash@5.0", name="bash",
                          version="5.0", status="recent")
        assert c.is_recently_active is True
        assert c.severity == RECENT_ACTIVITY_SEVERITY

    def test_older_is_not_recently_active(self):
        c = AgedComponent(purl="pkg:deb/bash@5.0", name="bash",
                          version="5.0", status="older")
        assert c.is_recently_active is False
        assert c.severity is None

    def test_no_vulns_is_not_recently_active(self):
        c = AgedComponent(purl="pkg:deb/foo@1.0", name="foo",
                          version="1.0", status="no_vulns")
        assert c.is_recently_active is False
        assert c.severity is None

    def test_to_dict_recent(self):
        c = AgedComponent(
            purl="pkg:deb/bash@5.0",
            name="bash",
            version="5.0",
            status="recent",
            most_recent_modified="2026-05-01T00:00:00Z",
            most_recent_cve="CVE-2026-1234",
            days_since_modified=35,
        )
        d = c.to_dict()
        assert d["status"] == "recent"
        assert d["most_recent_modified"] == "2026-05-01T00:00:00Z"
        assert d["most_recent_cve"] == "CVE-2026-1234"
        assert d["days_since_modified"] == 35
        assert d["severity"] == RECENT_ACTIVITY_SEVERITY

    def test_to_dict_no_vulns_has_no_severity(self):
        c = AgedComponent(purl="p", name="n", version="v", status="no_vulns")
        d = c.to_dict()
        assert "severity" not in d
        assert "most_recent_modified" not in d


# ---------------------------------------------------------------------------
# check() — the main integration
# ---------------------------------------------------------------------------

# Minimal Component stub for testing.
class _FakeComponent:
    def __init__(self, name, version, source="dpkg"):
        self.name = name
        self.version = version
        self.source = source

    def purl(self):
        return f"pkg:{self.source}/{self.name}@{self.version}"


class _FakeSbom:
    def __init__(self, components):
        self.components = components


def _now():
    return datetime.datetime.now(tz=datetime.timezone.utc)


class TestCheck:
    def _recent_ts(self, days_ago=10):
        dt = _now() - datetime.timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _old_ts(self, days_ago=200):
        dt = _now() - datetime.timedelta(days=days_ago)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _make_osv_record(self, cve_id, modified):
        return {"id": cve_id, "modified": modified}

    def test_empty_sbom_returns_empty_report(self):
        sbom = _FakeSbom([])
        with patch("embalmer.sbom_osv._osv_query", return_value=[]):
            report = check(sbom)
        assert isinstance(report, SbomAgeReport)
        assert report.components == []
        assert report.has_recent_activity is False

    def test_no_cvés_returns_no_vulns(self):
        sbom = _FakeSbom([_FakeComponent("bash", "5.0")])
        with patch("embalmer.sbom_osv._osv_query", return_value=[]):
            report = check(sbom, threshold_days=90)
        assert len(report.components) == 1
        c = report.components[0]
        assert c.status == "no_vulns"
        assert not c.is_recently_active

    def test_recent_record_flagged(self):
        sbom = _FakeSbom([_FakeComponent("bash", "5.0")])
        records = [self._make_osv_record("CVE-2026-9999", self._recent_ts(5))]
        with patch("embalmer.sbom_osv._osv_query", return_value=records):
            report = check(sbom, threshold_days=90)
        assert report.has_recent_activity is True
        assert report.recent_count == 1
        c = report.components[0]
        assert c.status == "recent"
        assert c.most_recent_cve == "CVE-2026-9999"
        assert c.days_since_modified == 5
        assert c.severity == RECENT_ACTIVITY_SEVERITY

    def test_old_record_not_flagged(self):
        sbom = _FakeSbom([_FakeComponent("bash", "5.0")])
        records = [self._make_osv_record("CVE-2020-1234", self._old_ts(365))]
        with patch("embalmer.sbom_osv._osv_query", return_value=records):
            report = check(sbom, threshold_days=90)
        assert report.has_recent_activity is False
        assert report.recent_count == 0
        c = report.components[0]
        assert c.status == "older"
        assert c.severity is None

    def test_record_without_modified_is_unknown_age(self):
        sbom = _FakeSbom([_FakeComponent("bash", "5.0")])
        records = [{"id": "CVE-2024-1111"}]  # no modified field
        with patch("embalmer.sbom_osv._osv_query", return_value=records):
            report = check(sbom, threshold_days=90)
        c = report.components[0]
        assert c.status == "unknown_age"
        assert not c.is_recently_active

    def test_non_package_db_components_skipped(self):
        # Only dpkg/opkg/apk components are in scope; binary-detected
        # (source="generic") are deliberately excluded.
        sbom = _FakeSbom([_FakeComponent("openssl", "1.0.1f", source="generic")])
        with patch("embalmer.sbom_osv._osv_query", return_value=[]) as mock_q:
            report = check(sbom)
        mock_q.assert_not_called()
        assert report.components == []

    def test_multiple_components_sorted_recent_first(self):
        comps = [
            _FakeComponent("bash", "5.0"),
            _FakeComponent("curl", "7.68.0"),
            _FakeComponent("libssl1.1", "1.1.1"),
        ]
        sbom = _FakeSbom(comps)
        bash_records = [self._make_osv_record("CVE-2026-1111", self._recent_ts(3))]
        curl_records = []  # no vulns
        ssl_records = [self._make_osv_record("CVE-2024-9999", self._old_ts(400))]

        def _fake_osv(purl, timeout):
            if "bash" in purl:
                return bash_records
            if "curl" in purl:
                return curl_records
            if "libssl" in purl:
                return ssl_records
            return []

        with patch("embalmer.sbom_osv._osv_query", side_effect=_fake_osv):
            report = check(sbom, threshold_days=90)

        assert report.has_recent_activity is True
        assert report.recent_count == 1
        assert report.older_count == 1
        assert report.no_vulns_count == 1
        # First entry should be the recent one
        assert report.components[0].status == "recent"
        assert report.components[0].name == "bash"

    def test_custom_threshold_days(self):
        sbom = _FakeSbom([_FakeComponent("bash", "5.0")])
        # A record modified 50 days ago should be recent with threshold=90
        # but NOT recent with threshold=30.
        records = [self._make_osv_record("CVE-2026-5555", self._recent_ts(50))]
        with patch("embalmer.sbom_osv._osv_query", return_value=records):
            report_90 = check(sbom, threshold_days=90)
            report_30 = check(sbom, threshold_days=30)
        assert report_90.components[0].status == "recent"
        assert report_30.components[0].status == "older"

    def test_to_dict_shape(self):
        sbom = _FakeSbom([_FakeComponent("bash", "5.0")])
        records = [self._make_osv_record("CVE-2026-1234", self._recent_ts(10))]
        with patch("embalmer.sbom_osv._osv_query", return_value=records):
            report = check(sbom, threshold_days=90)
        d = report.to_dict()
        assert "threshold_days" in d
        assert "has_recent_activity" in d
        assert "recent_count" in d
        assert "older_count" in d
        assert "no_vulns_count" in d
        assert "component_count" in d
        assert "components" in d
        assert d["threshold_days"] == 90
        assert d["has_recent_activity"] is True


# ---------------------------------------------------------------------------
# Gate integration via report serialization
# ---------------------------------------------------------------------------

class TestGateIntegration:
    """Verify the gate.py code path reads sbom.vuln_age correctly."""

    def test_recent_activity_counted_by_gate(self):
        from embalmer.gate import _iter_finding_severities

        report_dict = {
            "sbom": {
                "vuln_age": {
                    "threshold_days": 90,
                    "has_recent_activity": True,
                    "components": [
                        {
                            "purl": "pkg:deb/bash@5.0",
                            "name": "bash",
                            "version": "5.0",
                            "status": "recent",
                            "severity": "medium",
                        }
                    ],
                }
            }
        }
        severities = _iter_finding_severities(report_dict)
        assert "medium" in severities

    def test_older_not_counted(self):
        from embalmer.gate import _iter_finding_severities

        report_dict = {
            "sbom": {
                "vuln_age": {
                    "threshold_days": 90,
                    "has_recent_activity": False,
                    "components": [
                        {
                            "purl": "pkg:deb/bash@5.0",
                            "name": "bash",
                            "version": "5.0",
                            "status": "older",
                        }
                    ],
                }
            }
        }
        severities = _iter_finding_severities(report_dict)
        assert "medium" not in severities
