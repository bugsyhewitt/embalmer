"""Unit tests for report rendering (criterion 7)."""

from __future__ import annotations

import csv
import io
import json

from embalmer.models import ExtractionResult, Finding, Report
from embalmer.report import CSV_COLUMNS, render, to_csv, to_json, to_markdown
from embalmer.sbom import Component, Sbom


def _sample_report() -> Report:
    return Report(
        firmware="router.bin",
        checks=["extract", "creds", "binaries"],
        extraction=ExtractionResult(
            extraction_tree={"etc": {"shadow": {"_type": "file", "size": 42}}},
            file_count=1,
            extraction_time_ms=12,
            extract_root="/tmp/work",
        ),
        credentials=[
            Finding(category="credential", path="etc/shadow", type="password_hash",
                    detail="hash", severity="high"),
        ],
        binaries=[
            Finding(category="binary", path="bin/busybox", type="CWE-120",
                    detail="overflow", severity="high"),
        ],
    )


def test_json_roundtrip_has_all_sections():
    report = _sample_report()
    parsed = json.loads(to_json(report))
    assert parsed["firmware"] == "router.bin"
    assert "extraction" in parsed
    assert parsed["extraction"]["file_count"] == 1
    assert parsed["credentials"][0]["category"] == "credential"
    assert parsed["binaries"][0]["type"] == "CWE-120"


def test_markdown_contains_same_data():
    report = _sample_report()
    md = to_markdown(report)
    assert "router.bin" in md
    assert "Extraction" in md
    assert "Credential findings" in md
    assert "Binary findings" in md
    assert "etc/shadow" in md
    assert "CWE-120" in md
    assert "shadow" in md


def test_render_dispatch():
    report = _sample_report()
    assert render(report, "json").lstrip().startswith("{")
    assert render(report, "md").startswith("#")


def test_omitted_checks_absent_from_json():
    report = Report(firmware="x.bin", checks=["extract"],
                    extraction=ExtractionResult({}, 0, 0, "/tmp"))
    parsed = json.loads(to_json(report))
    assert "extraction" in parsed
    assert "credentials" not in parsed
    assert "binaries" not in parsed
    assert "sbom" not in parsed


def _report_with_sbom() -> Report:
    return Report(
        firmware="router.bin",
        checks=["sbom"],
        sbom=Sbom(
            components=[
                Component(
                    name="busybox", version="1.35.0-4", source="dpkg",
                    architecture="amd64", db_path="var/lib/dpkg/status",
                ),
            ]
        ),
    )


def test_sbom_serialized_in_json():
    report = _report_with_sbom()
    parsed = json.loads(to_json(report))
    assert "sbom" in parsed
    assert parsed["sbom"]["component_count"] == 1
    assert parsed["sbom"]["components"][0]["name"] == "busybox"
    # Full CycloneDX BOM embedded under the bom key.
    bom = parsed["sbom"]["bom"]
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["name"] == "router.bin"
    assert bom["components"][0]["purl"] == "pkg:deb/busybox@1.35.0-4?arch=amd64"


def test_sbom_rendered_in_markdown():
    report = _report_with_sbom()
    md = to_markdown(report)
    assert "Software Bill of Materials" in md
    assert "busybox" in md
    assert "pkg:deb/busybox@1.35.0-4" in md
    assert "CycloneDX" in md


# --- CSV export -------------------------------------------------------------


def _parse_csv(text: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    return reader.fieldnames or [], rows


def test_csv_header_is_fixed_columns():
    report = _sample_report()
    header, _rows = _parse_csv(to_csv(report))
    assert header == list(CSV_COLUMNS)


def test_csv_one_row_per_finding_across_sections():
    report = _sample_report()
    _header, rows = _parse_csv(to_csv(report))
    # The sample has one credential finding and one binary finding.
    assert len(rows) == 2
    by_cat = {r["category"]: r for r in rows}
    assert by_cat["credential"]["path"] == "etc/shadow"
    assert by_cat["credential"]["severity"] == "high"
    assert by_cat["credential"]["type"] == "password_hash"
    assert by_cat["binary"]["type"] == "CWE-120"
    # Singletons default to a count of 1, matching the markdown renderer.
    assert by_cat["binary"]["count"] == "1"


def test_csv_section_ordering_is_creds_certs_bins_components():
    report = Report(
        firmware="x.bin",
        checks=["creds", "certs", "binaries", "components"],
        credentials=[Finding(category="credential", path="a", type="t_cred")],
        certificates=[Finding(category="certificate", path="b", type="t_cert")],
        binaries=[Finding(category="binary", path="c", type="t_bin")],
        components=[Finding(category="component", path="d", type="t_comp")],
    )
    _header, rows = _parse_csv(to_csv(report))
    assert [r["category"] for r in rows] == [
        "credential",
        "certificate",
        "binary",
        "component",
    ]


def test_csv_includes_extra_fields_in_dedicated_columns():
    report = Report(
        firmware="x.bin",
        checks=["certs", "components"],
        certificates=[
            Finding(
                category="certificate", path="etc/ssl/cert.pem", type="x509",
                severity="medium", detail="self-signed",
                extra={
                    "subject_cn": "router.local",
                    "issuer_cn": "router.local",
                    "expiry": "2020-01-01",
                    "reason": "self-signed",
                },
            ),
        ],
        components=[
            Finding(
                category="component", path="bin/busybox", type="component",
                detail="BusyBox 1.21.1",
                extra={
                    "component": "busybox",
                    "version": "1.21.1",
                    "cpe": "cpe:2.3:a:busybox:busybox:1.21.1:*:*:*:*:*:*:*",
                },
            ),
        ],
    )
    _header, rows = _parse_csv(to_csv(report))
    cert_row = next(r for r in rows if r["category"] == "certificate")
    assert cert_row["subject_cn"] == "router.local"
    assert cert_row["expiry"] == "2020-01-01"
    assert cert_row["reason"] == "self-signed"
    comp_row = next(r for r in rows if r["category"] == "component")
    assert comp_row["component"] == "busybox"
    assert comp_row["version"] == "1.21.1"
    assert comp_row["cpe"].startswith("cpe:2.3:a:busybox")


def test_csv_escapes_commas_quotes_and_newlines_in_detail():
    report = Report(
        firmware="x.bin",
        checks=["creds"],
        credentials=[
            Finding(
                category="credential", path="etc/shadow", type="hash",
                detail='root:$1$abc, "weak"\nsecond line', severity="high",
            ),
        ],
    )
    text = to_csv(report)
    # Round-trips back to the exact value through a standard CSV reader.
    _header, rows = _parse_csv(text)
    assert rows[0]["detail"] == 'root:$1$abc, "weak"\nsecond line'


def test_csv_empty_report_is_header_only():
    report = Report(firmware="x.bin", checks=["extract"],
                    extraction=ExtractionResult({}, 0, 0, "/tmp"))
    text = to_csv(report)
    header, rows = _parse_csv(text)
    assert header == list(CSV_COLUMNS)
    assert rows == []


def test_csv_excludes_sbom_and_extraction_tree():
    report = _report_with_sbom()
    text = to_csv(report)
    # The SBOM components/BOM are not findings, so the CSV is header-only.
    _header, rows = _parse_csv(text)
    assert rows == []
    assert "busybox" not in text
    assert "CycloneDX" not in text


def test_render_dispatch_csv():
    report = _sample_report()
    out = render(report, "csv")
    assert out.splitlines()[0] == ",".join(CSV_COLUMNS)
