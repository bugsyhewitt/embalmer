"""Baseline diff: compare a fresh scan against a previously-saved scan.

When an operator upgrades firmware, the question is never "what does this image
contain?" — it is "what *changed* versus the last release?". Did the vendor
actually fix the CVE they claimed to? Did the patch quietly introduce a new
hardcoded credential? Did a package get added, removed, or bumped?

This module answers that. It takes the JSON report from a previous run
(``--baseline scan-output.json``) and the freshly-assembled :class:`Report` from
the current run, and emits a structured *delta*:

* **findings** — credential, certificate, and binary findings that are
  ``added`` (present now, absent before), ``removed`` (present before, gone now),
  or ``unchanged`` (present in both). Findings are matched by a stable identity
  that is deliberately independent of severity, so a finding whose *severity*
  changed between scans shows up under ``severity_changed`` rather than as a
  remove+add pair.
* **sbom** — package components ``added`` / ``removed`` / ``changed`` (same
  package name, different version — the patch-validation signal operators care
  about most).

The diff operates purely on the two reports' serialized ``to_dict()`` shapes, so
it works equally well whether the baseline came from a JSON file on disk or a
``Report`` produced in-process. Nothing here touches the filesystem or any
external tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Report

# Report sections that contain findings, matched 1:1 across the two scans.
_FINDING_SECTIONS = ("credentials", "certificates", "binaries")


class BaselineError(Exception):
    """Raised when the baseline file cannot be read or is not a valid report."""


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load and minimally validate a previously-saved JSON scan report.

    The baseline must be the JSON form of an embalmer report (i.e. the output of
    ``embalmer --format json``). We accept any object that looks like a report —
    a top-level ``firmware`` key is the cheap structural sanity check. We do
    *not* require the same checks to have run in both scans; sections missing
    from one side simply produce adds or removes.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {p}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "firmware" not in data:
        raise BaselineError(
            f"baseline {p} does not look like an embalmer JSON report "
            "(missing top-level 'firmware' key)"
        )
    return data


def _finding_identity(finding: dict[str, Any]) -> tuple[str, ...]:
    """A severity-independent identity for cross-scan finding matching.

    Two findings are "the same finding across scans" when they share their
    category, type, and an underlying-artifact discriminator — *not* when they
    share a severity (severity is enriched from live CVSS/EPSS/KEV data and can
    legitimately drift between two scans of unchanged content). Path is part of
    identity because "the same CWE in a different binary" is a different finding.

    The discriminator mirrors :func:`embalmer.summary._identity` but is computed
    from the serialized dict (findings flatten their ``extra`` into the dict via
    ``Finding.to_dict``), so it works on both a live report and a loaded
    baseline.
    """
    category = str(finding.get("category", ""))
    ftype = str(finding.get("type", ""))
    path = str(finding.get("path", ""))

    if category == "credential":
        disc = str(finding.get("key") or finding.get("detail") or "")
    elif category == "binary":
        parts = [
            str(finding.get("function") or ""),
            str(finding.get("symbol") or ""),
            str(finding.get("address") or ""),
        ]
        disc = "|".join(p for p in parts if p) or str(finding.get("detail") or "")
    else:  # certificate and any future category
        disc = str(finding.get("reason") or finding.get("detail") or "")

    return (category, ftype, path, disc)


def _index_findings(
    findings: list[dict[str, Any]],
) -> dict[tuple[str, ...], dict[str, Any]]:
    """Index a section's findings by identity, last-write-wins on collision.

    Findings should already be deduplicated by the pipeline's post-process pass,
    so collisions are not expected; if two share an identity we keep the last,
    which is harmless for a presence/severity comparison.
    """
    return {_finding_identity(f): f for f in findings}


@dataclass
class FindingsDelta:
    """Added / removed / unchanged / severity-changed findings for one section."""

    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    #: Entries are ``{"finding": <current>, "from": <old sev>, "to": <new sev>}``.
    severity_changed: list[dict[str, Any]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "unchanged": len(self.unchanged),
            "severity_changed": len(self.severity_changed),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts(),
            "added": self.added,
            "removed": self.removed,
            "severity_changed": self.severity_changed,
            "unchanged": self.unchanged,
        }


def diff_findings(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> FindingsDelta:
    """Compute the add/remove/unchanged/severity-changed delta for one section."""
    before_idx = _index_findings(before)
    after_idx = _index_findings(after)

    delta = FindingsDelta()

    for ident, cur in after_idx.items():
        old = before_idx.get(ident)
        if old is None:
            delta.added.append(cur)
            continue
        old_sev = old.get("severity")
        new_sev = cur.get("severity")
        if old_sev != new_sev:
            delta.severity_changed.append(
                {"finding": cur, "from": old_sev, "to": new_sev}
            )
        else:
            delta.unchanged.append(cur)

    for ident, old in before_idx.items():
        if ident not in after_idx:
            delta.removed.append(old)

    return delta


def _component_key(comp: dict[str, Any]) -> tuple[str, str]:
    """Identity for an SBOM component across scans: (source, name).

    Version is deliberately excluded so a version bump of the *same* package
    surfaces as ``changed`` rather than as a remove+add pair — that bump is the
    primary signal for patch validation.
    """
    return (str(comp.get("source", "")), str(comp.get("name", "")))


@dataclass
class SbomDelta:
    """Added / removed / version-changed / unchanged SBOM components."""

    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    #: Entries are ``{"component": <cur>, "from": <old ver>, "to": <new ver>}``.
    changed: list[dict[str, Any]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "unchanged": len(self.unchanged),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts(),
            "added": self.added,
            "removed": self.removed,
            "changed": self.changed,
            "unchanged": self.unchanged,
        }


def diff_sbom(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> SbomDelta:
    """Compute the add/remove/version-change/unchanged delta for SBOM components."""
    before_idx = {_component_key(c): c for c in before}
    after_idx = {_component_key(c): c for c in after}

    delta = SbomDelta()

    for key, cur in after_idx.items():
        old = before_idx.get(key)
        if old is None:
            delta.added.append(cur)
            continue
        old_ver = old.get("version")
        new_ver = cur.get("version")
        if old_ver != new_ver:
            delta.changed.append(
                {"component": cur, "from": old_ver, "to": new_ver}
            )
        else:
            delta.unchanged.append(cur)

    for key, old in before_idx.items():
        if key not in after_idx:
            delta.removed.append(old)

    return delta


@dataclass
class Diff:
    """The full baseline-vs-current delta."""

    baseline_firmware: str
    current_firmware: str
    findings: dict[str, FindingsDelta] = field(default_factory=dict)
    sbom: SbomDelta | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "diff": {
                "baseline_firmware": self.baseline_firmware,
                "current_firmware": self.current_firmware,
                "findings": {
                    section: delta.to_dict()
                    for section, delta in self.findings.items()
                },
            }
        }
        if self.sbom is not None:
            out["diff"]["sbom"] = self.sbom.to_dict()
        return out


def _section_findings(report_data: dict[str, Any], section: str) -> list[dict[str, Any]]:
    val = report_data.get(section)
    return val if isinstance(val, list) else []


def compute_diff(baseline: dict[str, Any], current: Report) -> Diff:
    """Compare a loaded baseline report dict against a live current :class:`Report`.

    Only sections present in *both* scans are diffed for findings; if a section
    ran in only one scan, every finding there is an unambiguous add or remove,
    so the section is still diffed (the absent side is treated as empty). SBOM is
    diffed only when at least one scan produced an ``sbom`` block.
    """
    current_data = current.to_dict()

    diff = Diff(
        baseline_firmware=str(baseline.get("firmware", "")),
        current_firmware=str(current_data.get("firmware", "")),
    )

    for section in _FINDING_SECTIONS:
        before = _section_findings(baseline, section)
        after = _section_findings(current_data, section)
        # Skip a section only when neither scan touched it at all.
        if not before and not after:
            if section not in baseline and section not in current_data:
                continue
        diff.findings[section] = diff_findings(before, after)

    base_sbom = baseline.get("sbom")
    cur_sbom = current_data.get("sbom")
    if base_sbom is not None or cur_sbom is not None:
        before_comps = (base_sbom or {}).get("components", []) if base_sbom else []
        after_comps = (cur_sbom or {}).get("components", []) if cur_sbom else []
        diff.sbom = diff_sbom(before_comps, after_comps)

    return diff


def render_markdown(diff: Diff) -> str:
    """Render a human-readable markdown summary of the delta."""
    data = diff.to_dict()["diff"]
    out: list[str] = []
    out.append("# Firmware Upgrade Diff")
    out.append("")
    out.append(f"**Baseline:** `{data['baseline_firmware']}`")
    out.append(f"**Current:** `{data['current_firmware']}`")
    out.append("")

    for section, delta in data["findings"].items():
        counts = delta["counts"]
        out.append(f"## {section.capitalize()}")
        out.append("")
        out.append(
            f"+{counts['added']} added, -{counts['removed']} removed, "
            f"~{counts['severity_changed']} severity-changed, "
            f"{counts['unchanged']} unchanged"
        )
        out.append("")
        if delta["added"]:
            out.append("### Added")
            for f in delta["added"]:
                out.append(
                    f"- **{f.get('severity', '?')}** {f.get('type', '?')} "
                    f"`{f.get('path', '?')}` — {f.get('detail', '')}"
                )
            out.append("")
        if delta["removed"]:
            out.append("### Removed (resolved)")
            for f in delta["removed"]:
                out.append(
                    f"- ~~**{f.get('severity', '?')}** {f.get('type', '?')} "
                    f"`{f.get('path', '?')}`~~ — {f.get('detail', '')}"
                )
            out.append("")
        if delta["severity_changed"]:
            out.append("### Severity changed")
            for entry in delta["severity_changed"]:
                f = entry["finding"]
                out.append(
                    f"- {f.get('type', '?')} `{f.get('path', '?')}`: "
                    f"{entry['from']} → {entry['to']}"
                )
            out.append("")

    if data.get("sbom"):
        sbom = data["sbom"]
        counts = sbom["counts"]
        out.append("## SBOM components")
        out.append("")
        out.append(
            f"+{counts['added']} added, -{counts['removed']} removed, "
            f"~{counts['changed']} version-changed, "
            f"{counts['unchanged']} unchanged"
        )
        out.append("")
        if sbom["added"]:
            out.append("### Added packages")
            for c in sbom["added"]:
                out.append(f"- {c.get('name')} {c.get('version')} ({c.get('source')})")
            out.append("")
        if sbom["removed"]:
            out.append("### Removed packages")
            for c in sbom["removed"]:
                out.append(f"- {c.get('name')} {c.get('version')} ({c.get('source')})")
            out.append("")
        if sbom["changed"]:
            out.append("### Version changes")
            for entry in sbom["changed"]:
                c = entry["component"]
                out.append(
                    f"- {c.get('name')}: {entry['from']} → {entry['to']}"
                )
            out.append("")

    return "\n".join(out)


def render(diff: Diff, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(diff.to_dict(), indent=2, sort_keys=False)
    if fmt == "md":
        return render_markdown(diff)
    raise ValueError(f"unknown format: {fmt!r}")
