"""Severity gate: CI exit-code policy for embalmer reports.

A vulnerability scanner is only as useful in CI as its ability to *fail the
build* when something serious shows up. embalmer already attaches a five-tier
severity label (``info`` / ``low`` / ``medium`` / ``high`` / ``critical``) to
every finding — credentials, certificates, binary CWEs, components — and to
every SBOM CVE match from the ``--sbom-cve`` / ``--sbom-osv`` cross-references.

This module turns that label into a gate. Operators pass
``--fail-on {info,low,medium,high,critical}`` (default: gate disabled) and
embalmer returns a non-zero exit code when *any* finding (across every section
the report carries) lands at or above the requested tier. The report itself is
still emitted in full — the gate observes, it does not suppress — so the CI
job's log shows exactly what tripped the gate.

The gate is deliberately *additive*: it touches no existing data path, has no
network calls, and when ``--fail-on`` is not passed every existing exit code is
byte-for-byte unchanged. Self-contained, no dependency, no I/O.

Design notes
------------

* **Threshold semantics are inclusive.** ``--fail-on high`` fails on
  ``high`` *and* ``critical``. The ladder is the same one the severity scoring
  pipeline already uses (:data:`embalmer.summary.SEVERITY_ORDER`).
* **What counts as a finding.** Every entry in the report's finding-bearing
  sections (``credentials``, ``certificates``, ``binaries``, ``components``)
  plus every entry in ``sbom.vulnerabilities`` (the CVE matches from
  ``--sbom-cve``/``--sbom-osv``). The SBOM CVE matches are the most actionable
  CI signal — a known-exploited CVE on a shipped library is the prototypical
  "fail the build" event — so they participate in the gate alongside the
  finding sections.
* **Unknown / non-ladder severities are ignored.** A finding tagged with a
  severity outside the canonical ladder (e.g. an upstream tool that emits
  ``"unknown"``) does not count toward the gate; the gate scores only on the
  documented ladder so its semantics are predictable.
* **Exit code 10.** Reserved for "gate triggered". The existing exit codes
  (0 success, 1 usage, 2 extraction, 3 binary analysis, 4 baseline, 5 fetch)
  are unchanged. 10 is distinct so a CI script can branch on
  ``failed-due-to-findings`` vs. ``failed-to-run``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Report
from .summary import SEVERITY_ORDER

#: Exit code returned when the gate triggers. Distinct from every other CLI
#: failure code so CI can tell "embalmer ran fine and found something bad" apart
#: from "embalmer failed to run".
GATE_EXIT_CODE = 10

#: The choices the ``--fail-on`` flag accepts on the command line. ``none``
#: disables the gate (the default); the five other tiers map to
#: :data:`SEVERITY_ORDER`.
FAIL_ON_CHOICES = ("none", "info", "low", "medium", "high", "critical")

# Rank in the ladder, highest-first (matches SEVERITY_ORDER). A finding's
# severity meets the threshold when its rank is <= the threshold's rank.
_RANK = {label: i for i, label in enumerate(SEVERITY_ORDER)}


@dataclass(frozen=True)
class GateResult:
    """The outcome of evaluating a report against a fail-on threshold.

    ``threshold`` is the severity label the gate was configured with (e.g.
    ``"high"``). ``triggered`` is True when at least one finding at or above
    the threshold was observed. ``counts`` is a ladder-ordered tally of every
    severity tier the report carries (zero buckets are omitted), suitable for
    a one-line CI log message.
    """

    threshold: str
    triggered: bool
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def offending_count(self) -> int:
        """How many findings landed at or above the threshold."""
        if self.threshold == "none":
            return 0
        thresh_rank = _RANK[self.threshold]
        return sum(
            n for label, n in self.counts.items()
            if label in _RANK and _RANK[label] <= thresh_rank
        )

    def summary_line(self) -> str:
        """One-line, stable text for a CI log."""
        if not self.counts:
            tally = "no findings"
        else:
            # Ladder order, so the line reads critical -> info regardless of
            # which severities the report actually carries.
            tally = ", ".join(
                f"{label}={self.counts[label]}"
                for label in SEVERITY_ORDER
                if self.counts.get(label, 0) > 0
            )
        verdict = "TRIGGERED" if self.triggered else "ok"
        return f"fail-on={self.threshold} [{verdict}]: {tally}"


def _iter_finding_severities(report_dict: dict[str, Any]) -> list[str]:
    """Walk every finding-bearing section of a serialized report.

    Operates on ``Report.to_dict()`` rather than the :class:`Report` dataclass
    so the gate sees exactly what a downstream consumer would see, including
    the merged SBOM CVE entries — which live under ``sbom.vulnerabilities`` and
    are not directly attributes of :class:`Report`.
    """
    severities: list[str] = []
    for section in ("credentials", "certificates", "binaries", "components"):
        items = report_dict.get(section)
        if not items:
            continue
        for finding in items:
            sev = finding.get("severity") if isinstance(finding, dict) else None
            if isinstance(sev, str):
                severities.append(sev)
    # SBOM CVE matches carry their own severity (from CVSS+EPSS+KEV scoring)
    # and live under sbom.vulnerabilities — pull each match's severity in too.
    sbom = report_dict.get("sbom")
    if isinstance(sbom, dict):
        vulns = sbom.get("vulnerabilities")
        # ``SbomCveReport.to_dict`` puts the list of matches under the same
        # ``vulnerabilities`` key inside the report object (the quick-look
        # shape), alongside ``cve_count`` and ``components_checked``.
        if isinstance(vulns, dict):
            for match in vulns.get("vulnerabilities", []) or []:
                if isinstance(match, dict):
                    sev = match.get("severity")
                    if isinstance(sev, str):
                        severities.append(sev)
    return severities


def evaluate(report: Report, threshold: str) -> GateResult:
    """Score a report against the fail-on threshold.

    A ``threshold`` of ``"none"`` always returns ``triggered=False`` but still
    populates ``counts`` so a CI log can show the tally without enforcing a
    gate (useful for "report-only" runs that want the same summary line).

    Any severity label outside :data:`SEVERITY_ORDER` is silently skipped — the
    gate's semantics are defined only on the documented ladder.
    """
    if threshold not in FAIL_ON_CHOICES:
        raise ValueError(
            f"unknown fail-on threshold {threshold!r}; "
            f"choose one of {FAIL_ON_CHOICES}"
        )
    report_dict = report.to_dict()
    severities = _iter_finding_severities(report_dict)

    counts: dict[str, int] = {}
    for sev in severities:
        if sev in _RANK:
            counts[sev] = counts.get(sev, 0) + 1

    if threshold == "none":
        return GateResult(threshold=threshold, triggered=False, counts=counts)

    thresh_rank = _RANK[threshold]
    triggered = any(
        _RANK[label] <= thresh_rank for label in counts
    )
    return GateResult(threshold=threshold, triggered=triggered, counts=counts)
