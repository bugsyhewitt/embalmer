"""SARIF 2.1.0 findings export.

SARIF (Static Analysis Results Interchange Format, OASIS standard) is the
lingua franca for security findings: GitHub Code Scanning, Azure DevOps,
GitLab, and most SAST dashboards ingest it directly. embalmer already emits
JSON (full report), markdown (human summary), and CSV (flat triage table);
SARIF is the missing CI/security-gate format — it is what lets a firmware audit
become a Code Scanning alert on a pull request without a bespoke converter.

This module renders the *same* ``Report`` finding inventory the CSV exporter
flattens (credentials, certificates, binaries, components) into a single SARIF
``run``. Like every other renderer it is a pure function of the ``Report``
object, so the SARIF can never disagree with the JSON/markdown/CSV views.

Design:

* One ``run`` whose ``tool.driver`` is embalmer. The firmware image is the
  logical artifact; each finding's ``path`` (a path *inside* the extracted
  firmware tree) becomes the result location's ``artifactLocation.uri``.
* Each distinct ``(category, type)`` pair becomes a reusable ``reportingDescriptor``
  (a SARIF "rule"), so e.g. every ``CWE-120`` binary finding shares one rule with
  a stable ``id`` and — when the type is a ``CWE-N`` string — a CWE ``tag`` and a
  relationship into the CWE external taxonomy. Downstream dashboards group and
  trend by rule id.
* ``Finding.severity`` maps to the SARIF result ``level`` (``error``/``warning``/
  ``note``) and, when a CVSS base score is present on the finding's
  ``severity_score`` block (the Rank 1 enrichment), to the numeric
  ``properties."security-severity"`` GitHub uses to rank alerts (0.0–10.0).
* CVE / EPSS / KEV evidence and the per-category ``extra`` fields ride along in
  the result ``properties`` so the verdict stays auditable and re-derivable.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub ingestion: https://docs.github.com/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import json
import re
from typing import Any

from .models import Report

#: SARIF schema version this exporter targets.
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/schemas/sarif-schema-2.1.0.json"
)

#: embalmer's own version, surfaced as the tool driver version. Imported lazily
#: from the package metadata so it tracks pyproject without a second source.
try:  # pragma: no cover - trivial import guard
    from . import __version__ as _EMBALMER_VERSION
except Exception:  # pragma: no cover
    _EMBALMER_VERSION = "0"

#: Report sections that hold a flat list of `Finding` dicts, in the order they
#: appear in the SARIF run. Deliberately identical to the CSV exporter's set:
#: SARIF is a *findings* document, so the SBOM/VEX documents and the extraction
#: tree are excluded (use `--format json` for those).
_FINDING_SECTIONS: tuple[str, ...] = (
    "credentials",
    "certificates",
    "binaries",
    "components",
)

#: embalmer severity label -> SARIF result level.
_LEVEL_BY_SEVERITY: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

#: GitHub's `security-severity` numeric bands, used only when a finding carries
#: no CVSS base score of its own (binary findings enriched by the Rank 1
#: pipeline supply a real CVSS, which always takes precedence).
_SECURITY_SEVERITY_BY_LABEL: dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}

_CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)

#: CWE taxonomy reference (one per run, referenced by relationships on rules
#: whose `type` is a CWE id). Kept minimal — a guid-less external reference is
#: valid SARIF and is what GitHub renders as a "CWE-N" chip.
_CWE_TAXONOMY = {
    "name": "CWE",
    "organization": "MITRE",
    "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
    "informationUri": "https://cwe.mitre.org/",
    "downloadUri": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "isComprehensive": False,
}


def _level_for(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get((severity or "info").lower(), "warning")


def _security_severity(finding: dict[str, Any], severity: str) -> str:
    """The numeric 0.0–10.0 score GitHub ranks alerts by.

    Prefer the real CVSS base score the Rank 1 enrichment attaches under
    ``severity_score.cvss``; fall back to a band derived from the coarse label
    so every result still sorts sensibly in a dashboard.
    """
    score = finding.get("severity_score")
    if isinstance(score, dict):
        cvss = score.get("cvss")
        if isinstance(cvss, (int, float)):
            # SARIF security-severity is a string; clamp into the CVSS range.
            return f"{max(0.0, min(10.0, float(cvss))):.1f}"
    return _SECURITY_SEVERITY_BY_LABEL.get((severity or "info").lower(), "5.0")


def _rule_id(category: str, type_: str) -> str:
    """Stable, dashboard-groupable rule id for a finding's (category, type).

    e.g. ``("binary", "CWE-120") -> "embalmer.binary.CWE-120"``. The type is
    sanitized so the id is always a safe token.
    """
    safe_type = re.sub(r"[^A-Za-z0-9._-]+", "_", type_ or "finding").strip("_") or "finding"
    safe_cat = re.sub(r"[^A-Za-z0-9._-]+", "_", category or "finding").strip("_") or "finding"
    return f"embalmer.{safe_cat}.{safe_type}"


def _build_rule(category: str, type_: str) -> dict[str, Any]:
    """A SARIF reportingDescriptor (rule) for one (category, type) pair."""
    rule_id = _rule_id(category, type_)
    text = f"{category} finding: {type_}"
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id.replace(".", "_"),
        "shortDescription": {"text": text},
        "fullDescription": {"text": text},
        "properties": {"category": category},
    }
    tags = [category]
    cwe_match = _CWE_RE.match(type_ or "")
    if cwe_match:
        cwe_id = f"CWE-{cwe_match.group(1)}"
        tags.append("security")
        tags.append(f"external/cwe/{cwe_id.lower()}")
        rule["properties"]["cwe"] = cwe_id
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
        # Relate the rule to the CWE external taxonomy so GitHub renders the chip.
        rule["relationships"] = [
            {
                "target": {
                    "id": cwe_id,
                    "toolComponent": {"name": "CWE"},
                },
                "kinds": ["relevant"],
            }
        ]
    rule["properties"]["tags"] = tags
    return rule


def _result_message(finding: dict[str, Any]) -> str:
    type_ = finding.get("type", "finding")
    detail = finding.get("detail", "")
    msg = f"{type_}"
    if detail:
        msg = f"{type_}: {detail}"
    count = finding.get("count")
    if isinstance(count, int) and count > 1:
        msg = f"{msg} ({count} occurrences)"
    return msg


#: Keys already represented by first-class SARIF fields — excluded from the
#: catch-all `properties` so the result isn't redundant.
_PROMOTED_KEYS = frozenset(
    {"category", "type", "path", "detail", "severity"}
)


def _result_properties(finding: dict[str, Any]) -> dict[str, Any]:
    """Auditable evidence: CVE/EPSS/KEV and the per-category extras."""
    props: dict[str, Any] = {}
    score = finding.get("severity_score")
    if isinstance(score, dict):
        for key in ("cve_id", "cvss", "epss", "in_kev", "epss_promoted"):
            if key in score:
                props[key] = score[key]
    # Carry the remaining `extra` fields (component/version/cpe, cert subject,
    # function/address/symbol, …) verbatim so the SARIF is self-describing.
    for key, value in finding.items():
        if key in _PROMOTED_KEYS or key == "severity_score":
            continue
        props.setdefault(key, value)
    return props


def to_sarif(report: Report, *, indent: int = 2) -> str:
    """Render `report`'s findings as a SARIF 2.1.0 JSON document string."""
    return json.dumps(to_sarif_dict(report), indent=indent, sort_keys=False)


def to_sarif_dict(report: Report) -> dict[str, Any]:
    """Build the SARIF 2.1.0 document as a plain dict (for tests/embedding)."""
    data = report.to_dict()

    rules_by_id: dict[str, dict[str, Any]] = {}
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    uses_cwe = False

    for section in _FINDING_SECTIONS:
        for finding in data.get(section) or []:
            category = finding.get("category", section.rstrip("s"))
            type_ = finding.get("type", "finding")
            rule_id = _rule_id(category, type_)
            if rule_id not in rules_by_id:
                rule = _build_rule(category, type_)
                rule_index[rule_id] = len(rules_by_id)
                rules_by_id[rule_id] = rule
                if "relationships" in rule:
                    uses_cwe = True

            severity = finding.get("severity", "info")
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": _level_for(severity),
                "message": {"text": _result_message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("path", "") or "(unknown)"
                            }
                        }
                    }
                ],
            }
            props = _result_properties(finding)
            props["security-severity"] = _security_severity(finding, severity)
            props["embalmer-severity"] = severity
            result["properties"] = props
            results.append(result)

    driver: dict[str, Any] = {
        "name": "embalmer",
        "informationUri": "https://github.com/bugsyhewitt/embalmer",
        "version": str(_EMBALMER_VERSION),
        "rules": list(rules_by_id.values()),
    }

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "properties": {"firmware": report.firmware, "checks": report.checks},
    }
    if uses_cwe:
        run["taxonomies"] = [_CWE_TAXONOMY]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
