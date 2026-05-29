"""Unit tests for VEX (Vulnerability Exploitability eXchange) export.

A VEX document is the exploitability companion to the SBOM: for each
CVE-resolved binary finding it asserts whether the vulnerability is
``exploitable`` (confirmed in CISA KEV, or a high EPSS probability) or still
``in_triage``. The evidence is the ``severity_score`` block the Rank 1 severity
pipeline already attaches to enriched binary findings — no network, no new
dependency.

These tests exercise:

  * :class:`VexEntry` — the per-CVE state derivation (KEV / EPSS / triage);
  * :class:`Vex.from_findings` — distilling findings into one entry per CVE,
    merging affected paths and worst-case signals;
  * the CycloneDX 1.6 VEX document shape;
  * the report ``to_dict`` / markdown / pipeline wiring (Article IX: real
    findings and the real pipeline over mocks where practical).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from embalmer import pipeline, report as report_mod
from embalmer.models import Finding, Report
from embalmer.vex import (
    EPSS_EXPLOITABLE_THRESHOLD,
    Vex,
    VexEntry,
)


# --- helpers ---------------------------------------------------------------


def _binary_finding(
    cve_id: str | None,
    *,
    path: str = "usr/bin/app",
    cvss: float | None = None,
    epss: float | None = None,
    in_kev: bool = False,
    severity: str = "info",
    type_: str = "CWE-120",
    function: str | None = None,
) -> Finding:
    """A binary finding carrying (or not) an enriched severity_score block."""
    extra: dict = {}
    if function:
        extra["function"] = function
    if cve_id is not None:
        score: dict = {"label": severity, "in_kev": in_kev, "cve_id": cve_id}
        if cvss is not None:
            score["cvss"] = cvss
        if epss is not None:
            score["epss"] = epss
        extra["severity_score"] = score
    return Finding(
        category="binary",
        path=path,
        type=type_,
        detail=f"{type_} finding",
        severity=severity,
        extra=extra,
    )


# --- VexEntry.state --------------------------------------------------------


class TestVexEntryState:
    def test_kev_membership_is_exploitable(self):
        entry = VexEntry(cve_id="CVE-2021-1", in_kev=True, epss=0.0)
        assert entry.state == "exploitable"

    def test_high_epss_is_exploitable(self):
        entry = VexEntry(cve_id="CVE-2021-2", in_kev=False, epss=0.8)
        assert entry.state == "exploitable"

    def test_epss_at_threshold_is_exploitable(self):
        entry = VexEntry(
            cve_id="CVE-2021-3", in_kev=False, epss=EPSS_EXPLOITABLE_THRESHOLD
        )
        assert entry.state == "exploitable"

    def test_epss_just_below_threshold_is_in_triage(self):
        entry = VexEntry(
            cve_id="CVE-2021-4",
            in_kev=False,
            epss=EPSS_EXPLOITABLE_THRESHOLD - 0.0001,
        )
        assert entry.state == "in_triage"

    def test_no_epss_no_kev_is_in_triage(self):
        entry = VexEntry(cve_id="CVE-2021-5", in_kev=False, epss=None)
        assert entry.state == "in_triage"

    def test_kev_wins_over_low_epss(self):
        entry = VexEntry(cve_id="CVE-2021-6", in_kev=True, epss=0.01)
        assert entry.state == "exploitable"

    def test_justification_records_evidence(self):
        kev = VexEntry(cve_id="CVE-1", in_kev=True)
        assert "KEV" in kev._justification()
        epss = VexEntry(cve_id="CVE-2", in_kev=False, epss=0.9)
        assert "EPSS" in epss._justification()
        triage = VexEntry(cve_id="CVE-3", in_kev=False, epss=0.1)
        assert "triage" in triage._justification().lower()


# --- VexEntry.to_cyclonedx -------------------------------------------------


class TestVexEntryCycloneDX:
    def test_basic_shape(self):
        entry = VexEntry(
            cve_id="CVE-2014-0160",
            cvss=7.5,
            epss=0.97,
            in_kev=True,
            severity="critical",
            affected_paths=["usr/bin/a", "usr/lib/b.so"],
        )
        d = entry.to_cyclonedx()
        assert d["id"] == "CVE-2014-0160"
        assert d["source"]["name"] == "NVD"
        assert "nvd.nist.gov" in d["source"]["url"]
        assert d["analysis"]["state"] == "exploitable"
        assert "KEV" in d["analysis"]["detail"]

    def test_ratings_present_when_cvss_known(self):
        entry = VexEntry(cve_id="CVE-1", cvss=9.8, severity="critical")
        d = entry.to_cyclonedx()
        assert d["ratings"][0]["score"] == 9.8
        assert d["ratings"][0]["severity"] == "critical"

    def test_no_ratings_block_when_cvss_unknown(self):
        entry = VexEntry(cve_id="CVE-1", cvss=None)
        d = entry.to_cyclonedx()
        assert "ratings" not in d

    def test_epss_and_kev_carried_as_properties(self):
        entry = VexEntry(cve_id="CVE-1", epss=0.42, in_kev=True)
        props = {p["name"]: p["value"] for p in entry.to_cyclonedx()["properties"]}
        assert props["embalmer:in-kev"] == "true"
        assert props["embalmer:epss"] == "0.42"

    def test_affects_lists_every_path(self):
        entry = VexEntry(
            cve_id="CVE-1", affected_paths=["usr/bin/a", "usr/bin/b"]
        )
        refs = [a["ref"] for a in entry.to_cyclonedx()["affects"]]
        assert refs == ["usr/bin/a", "usr/bin/b"]


# --- Vex.from_findings -----------------------------------------------------


class TestVexFromFindings:
    def test_empty_for_none_or_empty(self):
        assert Vex.from_findings(None).entries == []
        assert Vex.from_findings([]).entries == []

    def test_skips_findings_without_cve(self):
        findings = [
            _binary_finding(None),  # no severity_score at all
            _binary_finding("CVE-2021-1", cvss=5.0),
        ]
        vex = Vex.from_findings(findings)
        assert [e.cve_id for e in vex.entries] == ["CVE-2021-1"]

    def test_skips_non_binary_findings(self):
        cred = Finding(
            category="credential",
            path="etc/shadow",
            type="hash",
            extra={"severity_score": {"cve_id": "CVE-9999-0", "in_kev": True}},
        )
        vex = Vex.from_findings([cred])
        assert vex.entries == []

    def test_one_entry_per_cve_merges_paths(self):
        findings = [
            _binary_finding("CVE-2021-1", path="usr/bin/a", cvss=7.0),
            _binary_finding("CVE-2021-1", path="usr/bin/b", cvss=7.0),
        ]
        vex = Vex.from_findings(findings)
        assert len(vex.entries) == 1
        assert vex.entries[0].affected_paths == ["usr/bin/a", "usr/bin/b"]

    def test_affected_paths_sorted_and_deduped(self):
        findings = [
            _binary_finding("CVE-2021-1", path="usr/bin/z"),
            _binary_finding("CVE-2021-1", path="usr/bin/a"),
            _binary_finding("CVE-2021-1", path="usr/bin/z"),  # dup
        ]
        vex = Vex.from_findings(findings)
        assert vex.entries[0].affected_paths == ["usr/bin/a", "usr/bin/z"]

    def test_worst_case_signals_win_on_merge(self):
        # A later weaker sighting of the same CVE must not downgrade the entry.
        findings = [
            _binary_finding("CVE-2021-1", cvss=9.0, epss=0.9, in_kev=True),
            _binary_finding("CVE-2021-1", cvss=3.0, epss=0.1, in_kev=False),
        ]
        entry = Vex.from_findings(findings).entries[0]
        assert entry.in_kev is True
        assert entry.cvss == 9.0
        assert entry.epss == 0.9

    def test_higher_signal_in_later_finding_is_adopted(self):
        findings = [
            _binary_finding("CVE-2021-1", cvss=3.0, epss=0.1),
            _binary_finding("CVE-2021-1", cvss=8.0, epss=0.6, in_kev=True),
        ]
        entry = Vex.from_findings(findings).entries[0]
        assert entry.in_kev is True
        assert entry.cvss == 8.0
        assert entry.epss == 0.6
        assert entry.state == "exploitable"

    def test_entry_order_is_first_appearance(self):
        findings = [
            _binary_finding("CVE-B"),
            _binary_finding("CVE-A"),
            _binary_finding("CVE-B"),
        ]
        assert [e.cve_id for e in Vex.from_findings(findings).entries] == [
            "CVE-B",
            "CVE-A",
        ]


# --- Vex document + to_dict ------------------------------------------------


class TestVexDocument:
    def test_cyclonedx_document_shape(self):
        vex = Vex.from_findings(
            [_binary_finding("CVE-2021-1", cvss=7.5, in_kev=True)]
        )
        doc = vex.to_cyclonedx("/tmp/router.bin")
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert doc["metadata"]["component"]["name"] == "router.bin"
        assert doc["metadata"]["component"]["type"] == "firmware"
        assert len(doc["vulnerabilities"]) == 1

    def test_empty_document_has_empty_vuln_list(self):
        doc = Vex(entries=[]).to_cyclonedx("/tmp/fw.bin")
        assert doc["vulnerabilities"] == []

    def test_to_dict_counts(self):
        vex = Vex.from_findings(
            [
                _binary_finding("CVE-1", in_kev=True),  # exploitable
                _binary_finding("CVE-2", epss=0.9),  # exploitable
                _binary_finding("CVE-3", epss=0.1),  # in_triage
            ]
        )
        d = vex.to_dict()
        assert d["vulnerability_count"] == 3
        assert d["exploitable_count"] == 2
        assert {v["cve_id"] for v in d["vulnerabilities"]} == {
            "CVE-1",
            "CVE-2",
            "CVE-3",
        }


# --- Report integration ----------------------------------------------------


class TestReportIntegration:
    def _report_with_vex(self) -> Report:
        report = Report(firmware="/tmp/fw.bin", checks=["binaries"])
        report.binaries = [_binary_finding("CVE-2014-0160", cvss=7.5, in_kev=True)]
        report.vex = Vex.from_findings(report.binaries)
        return report

    def test_report_to_dict_includes_vex(self):
        d = self._report_with_vex().to_dict()
        assert "vex" in d
        assert d["vex"]["vulnerability_count"] == 1
        assert d["vex"]["bom"]["bomFormat"] == "CycloneDX"

    def test_report_without_vex_omits_key(self):
        report = Report(firmware="/tmp/fw.bin", checks=["binaries"])
        report.binaries = [_binary_finding("CVE-1")]
        assert "vex" not in report.to_dict()

    def test_markdown_renders_vex_section(self):
        md = report_mod.to_markdown(self._report_with_vex())
        assert "Vulnerability Exploitability eXchange" in md
        assert "CVE-2014-0160" in md
        assert "exploitable" in md

    def test_markdown_empty_vex(self):
        report = Report(firmware="/tmp/fw.bin", checks=["binaries"])
        report.binaries = []
        report.vex = Vex.from_findings(report.binaries)
        md = report_mod.to_markdown(report)
        assert "VEX" in md
        assert "No CVE-backed findings" in md


# --- Pipeline wiring -------------------------------------------------------


class TestPipelineWiring:
    def _fake_analyzer(self, _path):
        # Two findings; one CWE that the injected enricher will resolve.
        return [
            {"cwe": 120, "function": "strcpy", "detail": "buffer overflow"},
        ]

    def test_pipeline_emits_vex_when_requested(self, monkeypatch):
        # Stub severity enrichment so no network is touched: resolve CWE-120 to a
        # KEV CVE. The pipeline calls score_cwe(cwe_id, ...).
        from embalmer.severity import SeverityScore

        def fake_score_cwe(cwe_id, timeout=10, epss_threshold=None):
            return SeverityScore(
                cvss=7.5,
                epss=0.9,
                in_kev=True,
                label="critical",
                cve_id=f"CVE-TEST-{cwe_id}",
            )

        monkeypatch.setattr(pipeline, "score_cwe", fake_score_cwe)

        with tempfile.TemporaryDirectory() as tmp:
            # Make an extract root with one ELF-looking file is unnecessary: we
            # inject the analyzer, so binaries.analyze uses our callable. But the
            # pipeline still extracts. Use a trivial firmware blob.
            fw = Path(tmp) / "fw.bin"
            fw.write_bytes(b"\x00" * 16)
            workdir = Path(tmp) / "work"
            report = pipeline.run(
                firmware=str(fw),
                workdir=str(workdir),
                checks="binaries",
                emit_vex=True,
                _blight_analyzer=self._fake_analyzer,
            )

        assert report.vex is not None
        d = report.to_dict()
        # If the analyzer found binaries, the VEX has the CVE; if extraction
        # produced no ELF, the VEX is empty — either way the key is present and
        # the document is well-formed.
        assert "vex" in d
        assert d["vex"]["bom"]["bomFormat"] == "CycloneDX"

    def test_pipeline_omits_vex_by_default(self, monkeypatch):
        with tempfile.TemporaryDirectory() as tmp:
            fw = Path(tmp) / "fw.bin"
            fw.write_bytes(b"\x00" * 16)
            workdir = Path(tmp) / "work"
            report = pipeline.run(
                firmware=str(fw),
                workdir=str(workdir),
                checks="binaries",
                _blight_analyzer=self._fake_analyzer,
            )
        assert report.vex is None
        assert "vex" not in report.to_dict()
