"""Unit tests for the SARIF 2.1.0 findings export."""

from __future__ import annotations

import json

from embalmer.models import ExtractionResult, Finding, Report
from embalmer.report import render
from embalmer.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    to_sarif,
    to_sarif_dict,
)


def _report_with_findings() -> Report:
    return Report(
        firmware="router.bin",
        checks=["extract", "creds", "certs", "binaries", "components"],
        extraction=ExtractionResult(
            extraction_tree={"etc": {"shadow": {"_type": "file", "size": 42}}},
            file_count=1,
            extraction_time_ms=12,
            extract_root="/tmp/work",
        ),
        credentials=[
            Finding(
                category="credential",
                path="etc/shadow",
                type="password_hash",
                detail="root:$6$…",
                severity="high",
            ),
        ],
        certificates=[
            Finding(
                category="certificate",
                path="etc/ssl/server.crt",
                type="expired",
                detail="NotAfter 2019-01-01",
                severity="medium",
                extra={"subject_cn": "device.local", "reason": "expired"},
            ),
        ],
        binaries=[
            Finding(
                category="binary",
                path="bin/busybox",
                type="CWE-120",
                detail="buffer overflow in strcpy",
                severity="critical",
                extra={
                    "function": "main",
                    "address": "0x4011a0",
                    "severity_score": {
                        "label": "critical",
                        "in_kev": True,
                        "cvss": 9.8,
                        "epss": 0.92,
                        "cve_id": "CVE-2024-41592",
                    },
                },
            ),
        ],
        components=[
            Finding(
                category="component",
                path="lib/libssl.so.1.0.0",
                type="component",
                detail="OpenSSL 1.0.1f",
                severity="info",
                extra={
                    "component": "openssl",
                    "version": "1.0.1f",
                    "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
                },
            ),
        ],
    )


class TestEnvelope:
    def test_schema_and_version(self):
        doc = to_sarif_dict(_report_with_findings())
        assert doc["$schema"] == SARIF_SCHEMA
        assert doc["version"] == SARIF_VERSION
        assert SARIF_VERSION == "2.1.0"
        assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1

    def test_tool_driver_is_embalmer(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "embalmer"
        assert "github.com/bugsyhewitt/embalmer" in driver["informationUri"]
        # Version tracks the package metadata.
        assert driver["version"]

    def test_run_carries_firmware_and_checks(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        assert run["properties"]["firmware"] == "router.bin"
        assert "binaries" in run["properties"]["checks"]

    def test_is_valid_json_via_to_sarif(self):
        text = to_sarif(_report_with_findings())
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"


class TestResults:
    def test_one_result_per_finding_across_all_sections(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        # 1 credential + 1 certificate + 1 binary + 1 component
        assert len(run["results"]) == 4

    def test_result_location_uses_finding_path(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in run["results"]
        }
        assert "etc/shadow" in uris
        assert "bin/busybox" in uris

    def test_severity_maps_to_sarif_level(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        by_path = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r
            for r in run["results"]
        }
        assert by_path["bin/busybox"]["level"] == "error"  # critical
        assert by_path["etc/shadow"]["level"] == "error"  # high
        assert by_path["etc/ssl/server.crt"]["level"] == "warning"  # medium
        assert by_path["lib/libssl.so.1.0.0"]["level"] == "note"  # info

    def test_message_includes_type_and_detail(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        msgs = [r["message"]["text"] for r in run["results"]]
        assert any("CWE-120" in m and "buffer overflow" in m for m in msgs)

    def test_count_surfaced_in_message(self):
        report = Report(
            firmware="f.bin",
            checks=["creds"],
            credentials=[
                Finding(
                    category="credential",
                    path="etc/shadow",
                    type="password_hash",
                    severity="high",
                    extra={"count": 50, "paths": ["a", "b"]},
                )
            ],
        )
        run = to_sarif_dict(report)["runs"][0]
        assert "(50 occurrences)" in run["results"][0]["message"]["text"]


class TestRules:
    def test_distinct_category_type_pairs_become_rules(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "embalmer.binary.CWE-120" in rule_ids
        assert "embalmer.credential.password_hash" in rule_ids
        assert "embalmer.certificate.expired" in rule_ids
        assert "embalmer.component.component" in rule_ids

    def test_results_reference_rules_by_id_and_index(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            idx = result["ruleIndex"]
            assert rules[idx]["id"] == result["ruleId"]

    def test_repeated_finding_type_dedupes_to_one_rule(self):
        report = Report(
            firmware="f.bin",
            checks=["binaries"],
            binaries=[
                Finding(category="binary", path="bin/a", type="CWE-120", severity="high"),
                Finding(category="binary", path="bin/b", type="CWE-120", severity="high"),
            ],
        )
        run = to_sarif_dict(report)["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        cwe120 = [r for r in rules if r["id"] == "embalmer.binary.CWE-120"]
        assert len(cwe120) == 1
        assert len(run["results"]) == 2

    def test_cwe_rule_carries_cwe_metadata(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        rule = rules["embalmer.binary.CWE-120"]
        assert rule["properties"]["cwe"] == "CWE-120"
        assert "cwe.mitre.org/data/definitions/120" in rule["helpUri"]
        assert any("cwe" in t for t in rule["properties"]["tags"])
        assert rule["relationships"][0]["target"]["id"] == "CWE-120"

    def test_non_cwe_rule_has_no_cwe_relationship(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        assert "relationships" not in rules["embalmer.credential.password_hash"]


class TestSecuritySeverity:
    def test_cvss_drives_security_severity_when_present(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        binary = next(
            r
            for r in run["results"]
            if r["ruleId"] == "embalmer.binary.CWE-120"
        )
        # The 9.8 CVSS on severity_score wins over the label band.
        assert binary["properties"]["security-severity"] == "9.8"

    def test_label_band_used_when_no_cvss(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        cred = next(
            r
            for r in run["results"]
            if r["ruleId"] == "embalmer.credential.password_hash"
        )
        # `high` with no CVSS falls back to the band.
        assert cred["properties"]["security-severity"] == "8.0"


class TestEvidenceProperties:
    def test_cve_epss_kev_ride_along(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        binary = next(
            r
            for r in run["results"]
            if r["ruleId"] == "embalmer.binary.CWE-120"
        )
        props = binary["properties"]
        assert props["cve_id"] == "CVE-2024-41592"
        assert props["cvss"] == 9.8
        assert props["epss"] == 0.92
        assert props["in_kev"] is True

    def test_component_extras_carried(self):
        run = to_sarif_dict(_report_with_findings())["runs"][0]
        comp = next(
            r
            for r in run["results"]
            if r["ruleId"] == "embalmer.component.component"
        )
        props = comp["properties"]
        assert props["component"] == "openssl"
        assert props["cpe"].startswith("cpe:2.3:a:openssl")

    def test_taxonomy_present_only_when_cwe_findings_exist(self):
        with_cwe = to_sarif_dict(_report_with_findings())["runs"][0]
        assert any(t["name"] == "CWE" for t in with_cwe.get("taxonomies", []))

        no_cwe = to_sarif_dict(
            Report(
                firmware="f.bin",
                checks=["creds"],
                credentials=[
                    Finding(
                        category="credential",
                        path="etc/shadow",
                        type="password_hash",
                        severity="high",
                    )
                ],
            )
        )["runs"][0]
        assert "taxonomies" not in no_cwe


class TestEmptyAndUnrun:
    def test_empty_report_is_valid_sarif_with_no_results(self):
        report = Report(firmware="empty.bin", checks=["extract"])
        doc = to_sarif_dict(report)
        run = doc["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
        # Still parseable.
        json.loads(to_sarif(report))

    def test_unrun_sections_contribute_no_results(self):
        # credentials=None means "creds check did not run".
        report = Report(
            firmware="f.bin",
            checks=["binaries"],
            credentials=None,
            binaries=[
                Finding(category="binary", path="bin/x", type="CWE-78", severity="high")
            ],
        )
        run = to_sarif_dict(report)["runs"][0]
        assert len(run["results"]) == 1


class TestRenderDispatch:
    def test_render_sarif_matches_to_sarif(self):
        report = _report_with_findings()
        assert render(report, "sarif") == to_sarif(report)

    def test_render_sarif_is_json(self):
        report = _report_with_findings()
        parsed = json.loads(render(report, "sarif"))
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "embalmer"
