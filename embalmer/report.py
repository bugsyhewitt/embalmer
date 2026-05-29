"""Report rendering: JSON, markdown, CSV, and SARIF.

Every format renders the exact same `Report` object so they can never
disagree. JSON is a direct serialization; markdown is a human-readable summary
that exposes the same extraction tree, credential findings, and binary
findings. CSV is a flat, one-row-per-finding table of every finding the run
surfaced (credentials, certificates, binaries, and components) — the shape an
analyst imports straight into a spreadsheet or triage tool. SARIF (2.1.0) is
the same finding inventory in the OASIS standard format that GitHub Code
Scanning and most SAST dashboards ingest directly — see `embalmer/sarif.py`.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .models import Report
from .sarif import to_sarif

#: Columns emitted by the CSV findings export, in order. The first six are the
#: fields every `Finding` carries; the remainder are the union of the
#: per-category `extra` fields that are useful in a triage spreadsheet. A
#: finding that doesn't carry a given extra leaves that cell blank. Adding a
#: column here (never reordering/removing) is the only forward-compatible
#: change — downstream consumers key on the header row.
CSV_COLUMNS: tuple[str, ...] = (
    "category",
    "severity",
    "type",
    "path",
    "count",
    "detail",
    "component",
    "version",
    "cpe",
    "subject_cn",
    "issuer_cn",
    "expiry",
    "reason",
    "user",
    "password",
)


def to_json(report: Report, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


def _render_tree(tree: dict[str, Any], prefix: str = "") -> list[str]:
    lines: list[str] = []
    names = list(tree.keys())
    for idx, name in enumerate(names):
        node = tree[name]
        is_last = idx == len(names) - 1
        branch = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")
        if isinstance(node, dict) and node.get("_type") == "file":
            lines.append(f"{prefix}{branch}{name} ({node.get('size', 0)} B)")
        elif isinstance(node, dict) and node.get("_type") == "symlink":
            lines.append(f"{prefix}{branch}{name} -> {node.get('target', '?')}")
        elif isinstance(node, dict):
            lines.append(f"{prefix}{branch}{name}/")
            lines.extend(_render_tree(node, child_prefix))
        else:
            lines.append(f"{prefix}{branch}{name}")
    return lines


def to_markdown(report: Report) -> str:
    data = report.to_dict()
    out: list[str] = []
    out.append(f"# Firmware Audit Report: `{data['firmware']}`")
    out.append("")
    out.append(f"**Checks run:** {', '.join(data['checks'])}")
    out.append("")

    if "summary" in data:
        summary = data["summary"]
        out.append("## Summary")
        out.append("")
        out.append(f"**Total findings:** {summary['total']}")
        out.append("")
        by_sev = summary.get("by_severity", {})
        if by_sev:
            out.append("| Severity | Count |")
            out.append("|---|---|")
            for sev, count in by_sev.items():
                out.append(f"| {sev} | {count} |")
            out.append("")
        by_cat = summary.get("by_category", {})
        if by_cat:
            out.append("| Category | Count |")
            out.append("|---|---|")
            for cat, count in by_cat.items():
                out.append(f"| {cat} | {count} |")
            out.append("")

    if "extraction" in data:
        ext = data["extraction"]
        out.append("## Extraction")
        out.append("")
        out.append(f"- **Files extracted:** {ext['file_count']}")
        out.append(f"- **Extraction time:** {ext['extraction_time_ms']} ms")
        out.append(f"- **Extract root:** `{ext['extract_root']}`")
        if ext.get("extractor_used"):
            out.append(f"- **Extractor:** {ext['extractor_used']}")
        out.append("")
        out.append("### Extraction tree")
        out.append("")
        out.append("```")
        tree_lines = _render_tree(ext["extraction_tree"])
        out.extend(tree_lines if tree_lines else ["(empty)"])
        out.append("```")
        out.append("")

    if "credentials" in data:
        creds = data["credentials"]
        out.append("## Credential findings")
        out.append("")
        if not creds:
            out.append("_No credential findings._")
        else:
            out.append("| Severity | Type | Path | Count | Detail |")
            out.append("|---|---|---|---|---|")
            for f in creds:
                out.append(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` "
                    f"| {f.get('count', 1)} | {f['detail']} |"
                )
        out.append("")

    if "certificates" in data:
        certs = data["certificates"]
        out.append("## Certificate findings")
        out.append("")
        if not certs:
            out.append("_No certificate findings._")
        else:
            out.append(
                "| Severity | Type | Path | Subject CN | Issuer CN | Expiry | Reason |"
            )
            out.append("|---|---|---|---|---|---|---|")
            for f in certs:
                out.append(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` "
                    f"| {f.get('subject_cn') or '-'} "
                    f"| {f.get('issuer_cn') or '-'} "
                    f"| {f.get('expiry') or '-'} "
                    f"| {f.get('reason') or f['detail']} |"
                )
        out.append("")

    if "binaries" in data:
        bins = data["binaries"]
        out.append("## Binary findings (via blight)")
        out.append("")
        if not bins:
            out.append("_No binary findings._")
        else:
            out.append("| Severity | Type | Path | Count | Detail |")
            out.append("|---|---|---|---|---|")
            for f in bins:
                out.append(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` "
                    f"| {f.get('count', 1)} | {f['detail']} |"
                )
        out.append("")

    if "components" in data:
        comps = data["components"]
        out.append("## Third-party components")
        out.append("")
        if not comps:
            out.append("_No third-party components detected._")
        else:
            out.append("| Component | Version | Path | Count | CPE |")
            out.append("|---|---|---|---|---|")
            for f in comps:
                out.append(
                    f"| {f.get('component', f['type'])} "
                    f"| {f.get('version', '-')} | `{f['path']}` "
                    f"| {f.get('count', 1)} | `{f.get('cpe', '-')}` |"
                )
        out.append("")

    if "binary_groups" in data and data["binary_groups"]:
        out.append("## Binary findings by binary")
        out.append("")
        for group in data["binary_groups"]:
            out.append(
                f"- `{group['path']}` — {group['finding_count']} finding(s)"
            )
        out.append("")

    if "sbom" in data:
        sbom = data["sbom"]
        comps = sbom.get("components", [])
        out.append("## Software Bill of Materials (SBOM)")
        out.append("")
        out.append(f"**Components:** {sbom.get('component_count', len(comps))}")
        out.append("")
        if "bom" in sbom:
            out.append(
                "_CycloneDX "
                f"{sbom.get('bom', {}).get('specVersion', '1.6')} "
                "BOM available under the `sbom.bom` key of the JSON report._"
            )
            out.append("")
        if "spdx" in sbom:
            out.append(
                "_SPDX "
                f"{sbom.get('spdx', {}).get('spdxVersion', 'SPDX-2.3')} "
                "document available under the `sbom.spdx` key of the JSON report._"
            )
            out.append("")
        if not comps:
            out.append("_No packages found._")
        else:
            out.append("| Source | Name | Version | Arch | purl |")
            out.append("|---|---|---|---|---|")
            for c in comps:
                out.append(
                    f"| {c['source']} | {c['name']} | {c['version']} "
                    f"| {c.get('architecture') or '-'} | `{c['purl']}` |"
                )
        out.append("")
        if "ntia" in sbom:
            ntia = sbom["ntia"]
            out.append("### NTIA minimum-elements conformance")
            out.append("")
            verdict = "COMPLIANT" if ntia.get("compliant") else "NOT COMPLIANT"
            out.append(
                f"**{ntia.get('standard', 'NTIA Minimum Elements')}:** {verdict}  "
                f"({ntia.get('elements_satisfied', 0)}/"
                f"{ntia.get('elements_total', 0)} elements met)"
            )
            out.append("")
            missing = ntia.get("missing_elements", [])
            if missing:
                out.append(f"**Missing:** {', '.join(missing)}")
                out.append("")
            out.append("| Element | Met | Detail |")
            out.append("|---|---|---|")
            for e in ntia.get("elements", []):
                met = "yes" if e.get("satisfied") else "no"
                out.append(
                    f"| {e['label']} | {met} | {e.get('detail', '')} |"
                )
            out.append("")
        if "spdx_validation" in sbom:
            sv = sbom["spdx_validation"]
            out.append("### SPDX relationship-graph validation")
            out.append("")
            verdict = "VALID" if sv.get("valid") else "INVALID"
            out.append(
                f"**{sv.get('standard', 'SPDX relationship-graph validation')}:**"
                f" {verdict}  "
                f"({sv.get('checks_passed', 0)}/"
                f"{sv.get('checks_total', 0)} checks passed)"
            )
            out.append("")
            failed = sv.get("failed_checks", [])
            if failed:
                out.append(f"**Failed:** {', '.join(failed)}")
                out.append("")
            out.append("| Check | Passed | Detail |")
            out.append("|---|---|---|")
            for c in sv.get("checks", []):
                ok = "yes" if c.get("passed") else "no"
                out.append(
                    f"| {c['label']} | {ok} | {c.get('detail', '')} |"
                )
            out.append("")
        if "purl_validation" in sbom:
            pv = sbom["purl_validation"]
            out.append("### CycloneDX purl validation")
            out.append("")
            verdict = "VALID" if pv.get("valid") else "INVALID"
            out.append(
                f"**{pv.get('standard', 'package-url (purl) validation')}:**"
                f" {verdict}  "
                f"({pv.get('checks_passed', 0)}/"
                f"{pv.get('checks_total', 0)} checks passed)"
            )
            out.append("")
            failed = pv.get("failed_checks", [])
            if failed:
                out.append(f"**Failed:** {', '.join(failed)}")
                out.append("")
            out.append("| Check | Passed | Detail |")
            out.append("|---|---|---|")
            for c in pv.get("checks", []):
                ok = "yes" if c.get("passed") else "no"
                out.append(
                    f"| {c['label']} | {ok} | {c.get('detail', '')} |"
                )
            out.append("")
        if "vulnerabilities" in sbom:
            cve = sbom["vulnerabilities"]
            vulns = cve.get("vulnerabilities", [])
            out.append("### NVD CVE cross-reference")
            out.append("")
            out.append(
                f"**CVEs:** {cve.get('cve_count', len(vulns))} across "
                f"{cve.get('components_with_cves', 0)} of "
                f"{cve.get('components_checked', 0)} CPE-bearing component(s)"
            )
            out.append("")
            if not vulns:
                out.append("_No CVEs matched (or run was offline)._")
                out.append("")
            else:
                out.append("| CVE | Component (purl) | CVSS | Severity | KEV |")
                out.append("|---|---|---|---|---|")
                for v in vulns:
                    kev = "yes" if v.get("in_kev") else "no"
                    cvss = v.get("cvss")
                    out.append(
                        f"| {v['cve_id']} | `{v.get('purl', '')}` "
                        f"| {cvss if cvss is not None else '-'} "
                        f"| {v.get('severity', 'info')} | {kev} |"
                    )
                out.append("")

    if "vex" in data:
        vex = data["vex"]
        vulns = vex.get("vulnerabilities", [])
        out.append("## Vulnerability Exploitability eXchange (VEX)")
        out.append("")
        out.append(
            f"**Vulnerabilities:** {vex.get('vulnerability_count', len(vulns))}  "
            f"(**exploitable:** {vex.get('exploitable_count', 0)})"
        )
        out.append("")
        out.append(
            "_CycloneDX "
            f"{vex.get('bom', {}).get('specVersion', '1.6')} "
            "VEX document available under the `vex.bom` key of the JSON report._"
        )
        out.append("")
        if not vulns:
            out.append("_No CVE-backed findings to assert on._")
        else:
            out.append("| CVE | State | Severity | CVSS | EPSS | In KEV |")
            out.append("|---|---|---|---|---|---|")
            for v in vulns:
                out.append(
                    f"| {v['cve_id']} | {v['state']} | {v.get('severity', '-')} "
                    f"| {v.get('cvss') if v.get('cvss') is not None else '-'} "
                    f"| {v.get('epss') if v.get('epss') is not None else '-'} "
                    f"| {'yes' if v.get('in_kev') else 'no'} |"
                )
        out.append("")

    return "\n".join(out)


#: Report sections that hold a flat list of `Finding` dicts, in the order they
#: appear in the CSV. The SBOM (CycloneDX/SPDX documents) and the extraction
#: tree are deliberately excluded — CSV is the *findings* export, and a nested
#: BOM/tree does not flatten to one row per finding. Use `--format json` for
#: those.
_CSV_FINDING_SECTIONS: tuple[str, ...] = (
    "credentials",
    "certificates",
    "binaries",
    "components",
)


def to_csv(report: Report) -> str:
    """Render every finding as one CSV row.

    Iterates the credential, certificate, binary, and component sections (in
    that order) and emits a row per finding using the fixed `CSV_COLUMNS`
    header. Sections that did not run, or ran and found nothing, simply
    contribute no rows. The header is always emitted so an empty report is
    still a valid CSV (header-only).
    """
    data = report.to_dict()
    buf = io.StringIO()
    # QUOTE_MINIMAL + the csv module handle commas, quotes, and newlines inside
    # detail/reason strings correctly; line_terminator is normalized to "\n".
    writer = csv.DictWriter(
        buf,
        fieldnames=CSV_COLUMNS,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for section in _CSV_FINDING_SECTIONS:
        for finding in data.get(section) or []:
            row = {col: finding.get(col, "") for col in CSV_COLUMNS}
            # `count` defaults to 1 for singletons that never went through the
            # dedup pass, matching the markdown renderer.
            if row["count"] == "":
                row["count"] = finding.get("count", 1)
            writer.writerow(row)
    return buf.getvalue()


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return to_json(report)
    if fmt == "md":
        return to_markdown(report)
    if fmt == "csv":
        return to_csv(report)
    if fmt == "sarif":
        return to_sarif(report)
    raise ValueError(f"unknown format: {fmt!r}")
