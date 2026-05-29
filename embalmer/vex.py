"""VEX (Vulnerability Exploitability eXchange) export.

A VEX document answers the question a raw SBOM cannot: *of the vulnerabilities
that touch this firmware, which ones are actually exploitable?* It is the
companion artifact to the SBOM under EO-14028 — an SBOM inventories components, a
VEX asserts each vulnerability's exploitability status so downstream consumers
can suppress the noise (NTIA "VEX use case" framing).

embalmer already has everything a VEX needs and was, until now, throwing it away
at render time. The Rank 1 severity-scoring pipeline
(:mod:`embalmer.severity`) resolves each binary CWE finding to a representative
NVD CVE and enriches it with three exploitability signals:

* **CISA KEV membership** — confirmed exploited in the wild. The strongest
  possible exploitability assertion.
* **EPSS probability** — the model's estimate that the CVE will be exploited in
  the next 30 days.
* **CVSS base score** — the static severity tier.

This module folds those signals into a **CycloneDX 1.6 VEX** document
(``vulnerabilities`` array, each carrying an ``analysis`` block). The mapping
from embalmer's evidence to the CycloneDX VEX vocabulary is deliberately
conservative — embalmer asserts ``exploitable`` only when it has *confirmed*
exploitation evidence (KEV) or a model probability over the EPSS promotion
threshold, and otherwise leaves the vulnerability ``in_triage`` (the honest
"a human still needs to look at this" state). It never asserts
``not_affected``/``resolved`` because embalmer cannot prove a negative from
firmware strings alone.

Everything here is a pure transform over the already-enriched in-memory model:
no network, no filesystem, no new dependency. If severity enrichment was skipped
(``--no-enrich``) there is no CVE evidence to speak of, so the VEX is simply
empty — a valid, honest "nothing asserted" document.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import Finding

# CycloneDX spec version. 1.6 is the ECMA-424 release whose `vulnerabilities`
# array + `analysis` block is the native VEX carrier, matching the SBOM export.
CYCLONEDX_SPEC_VERSION = "1.6"

# EPSS probability at/above which embalmer is willing to assert `exploitable`
# from the model alone (no KEV confirmation). This mirrors the severity
# pipeline's default promotion threshold (`SeverityScore.EPSS_PROMOTE_THRESHOLD`)
# — "more likely than not to be exploited" — so the two subsystems agree on what
# "likely exploited" means.
EPSS_EXPLOITABLE_THRESHOLD = 0.5

# CycloneDX `analysis.state` enum values used here.
_STATE_EXPLOITABLE = "exploitable"
_STATE_IN_TRIAGE = "in_triage"


@dataclass
class VexEntry:
    """One vulnerability's exploitability assertion, distilled from a finding.

    A single CVE may be implicated by several binary findings (the same CWE in
    several binaries resolves to the same representative CVE); entries are keyed
    by ``cve_id`` so the VEX carries one assertion per vulnerability, with every
    affected binary recorded under ``affected_paths``.
    """

    cve_id: str
    cvss: float | None = None
    epss: float | None = None
    in_kev: bool = False
    severity: str = "info"
    # Every binary path the CVE was implicated by, sorted for stable output.
    affected_paths: list[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        """The CycloneDX VEX ``analysis.state`` embalmer asserts.

        ``exploitable`` only when there is confirmed in-the-wild exploitation
        (KEV) or a high EPSS probability; otherwise ``in_triage`` — the honest
        "not yet assessed" state. embalmer never claims ``not_affected`` or
        ``resolved`` because it cannot prove a negative from firmware evidence.
        """
        if self.in_kev:
            return _STATE_EXPLOITABLE
        if self.epss is not None and self.epss >= EPSS_EXPLOITABLE_THRESHOLD:
            return _STATE_EXPLOITABLE
        return _STATE_IN_TRIAGE

    def _justification(self) -> str:
        """Human-readable rationale recorded in ``analysis.detail``.

        Makes the state auditable: a reader can see *why* a CVE was called
        exploitable (KEV vs. EPSS) or left in triage.
        """
        if self.in_kev:
            return (
                "Listed in CISA KEV (Known Exploited Vulnerabilities) — "
                "confirmed exploited in the wild."
            )
        if self.epss is not None and self.epss >= EPSS_EXPLOITABLE_THRESHOLD:
            return (
                f"EPSS exploitation probability {self.epss:.2f} >= "
                f"{EPSS_EXPLOITABLE_THRESHOLD:.2f} (more likely than not to be "
                "exploited)."
            )
        return (
            "Resolved to a representative CVE via CWE; no confirmed exploitation "
            "evidence (not in KEV, EPSS below threshold). Requires analyst triage."
        )

    def to_cyclonedx(self) -> dict[str, Any]:
        """Render this entry as a CycloneDX 1.6 ``vulnerabilities[]`` object."""
        vuln: dict[str, Any] = {
            "id": self.cve_id,
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{self.cve_id}",
            },
            "analysis": {
                "state": self.state,
                "detail": self._justification(),
            },
        }
        ratings: list[dict[str, Any]] = []
        if self.cvss is not None:
            ratings.append(
                {
                    "source": {"name": "NVD"},
                    "score": self.cvss,
                    "severity": self.severity,
                    "method": "CVSSv31",
                }
            )
        if ratings:
            vuln["ratings"] = ratings
        # EPSS and KEV are exploitability signals, not CVSS ratings — carry them
        # as first-class properties so a consumer can re-derive the state.
        properties: list[dict[str, str]] = [
            {"name": "embalmer:in-kev", "value": "true" if self.in_kev else "false"},
        ]
        if self.epss is not None:
            properties.append(
                {"name": "embalmer:epss", "value": f"{self.epss}"}
            )
        vuln["properties"] = properties
        if self.affected_paths:
            # CycloneDX `affects` references components; embalmer's binary
            # findings are not BOM components, so the affected binaries are
            # recorded as bom-ref-free `ref` strings (the binary path), which is
            # spec-valid and keeps the linkage to the firmware tree.
            vuln["affects"] = [
                {"ref": path} for path in self.affected_paths
            ]
        return vuln


def _entries_from_findings(findings: list["Finding"]) -> list[VexEntry]:
    """Distill enriched binary findings into one :class:`VexEntry` per CVE.

    Only binary findings carrying a ``severity_score`` with a resolved
    ``cve_id`` contribute — that is the evidence the severity pipeline produced.
    Findings are visited in order; entries are keyed by CVE so repeated CVEs
    merge, accumulating their affected binary paths. The worst-case signal wins
    on merge (KEV sticks, the higher CVSS/EPSS is kept) so the assertion is
    never *weakened* by a later, weaker sighting of the same CVE.
    """
    entries: dict[str, VexEntry] = {}
    order: list[str] = []
    for finding in findings:
        if finding.category != "binary":
            continue
        score = finding.extra.get("severity_score")
        if not isinstance(score, dict):
            continue
        cve_id = score.get("cve_id")
        if not cve_id:
            continue
        cvss = score.get("cvss")
        epss = score.get("epss")
        in_kev = bool(score.get("in_kev"))
        if cve_id not in entries:
            entries[cve_id] = VexEntry(
                cve_id=cve_id,
                cvss=cvss,
                epss=epss,
                in_kev=in_kev,
                severity=finding.severity,
            )
            order.append(cve_id)
        entry = entries[cve_id]
        # Merge worst-case signals so a later weaker sighting can't downgrade.
        entry.in_kev = entry.in_kev or in_kev
        if cvss is not None and (entry.cvss is None or cvss > entry.cvss):
            entry.cvss = cvss
            entry.severity = finding.severity
        if epss is not None and (entry.epss is None or epss > entry.epss):
            entry.epss = epss
        # Record every binary the CVE was implicated by (deduped, sorted later).
        if finding.path and finding.path not in entry.affected_paths:
            entry.affected_paths.append(finding.path)
    result = [entries[c] for c in order]
    for entry in result:
        entry.affected_paths.sort()
    return result


@dataclass
class Vex:
    """A VEX document built from a report's enriched binary findings."""

    entries: list[VexEntry] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list["Finding"] | None) -> "Vex":
        """Build a :class:`Vex` from a report's binary findings (or ``None``)."""
        if not findings:
            return cls(entries=[])
        return cls(entries=_entries_from_findings(findings))

    def to_cyclonedx(
        self, firmware: str, timestamp: datetime.datetime | None = None
    ) -> dict[str, Any]:
        """Render a complete CycloneDX 1.6 VEX document.

        ``firmware`` names the subject (recorded as the root
        ``metadata.component``); ``timestamp`` defaults to now (UTC). The
        document is a CycloneDX BOM whose payload is the ``vulnerabilities``
        array — the CycloneDX-native VEX shape, so it drops straight into any
        VEX-aware consumer (Dependency-Track, grype's VEX ignore, etc.).
        """
        ts = timestamp or datetime.datetime.now(datetime.timezone.utc)
        return {
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "version": 1,
            "metadata": {
                "timestamp": ts.isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "embalmer",
                            "group": "necromancer",
                        }
                    ]
                },
                "component": {
                    "type": "firmware",
                    "name": Path(firmware).name or firmware,
                },
            },
            "vulnerabilities": [e.to_cyclonedx() for e in self.entries],
        }

    def to_dict(self) -> dict[str, Any]:
        """The summary shape attached to the embalmer report's ``vex`` key.

        ``vulnerability_count`` and the per-CVE ``vulnerabilities`` summary are
        the quick-look fields; the full CycloneDX VEX document is emitted under
        the ``bom`` key by :meth:`embalmer.models.Report.to_dict`.
        """
        return {
            "vulnerability_count": len(self.entries),
            "exploitable_count": sum(
                1 for e in self.entries if e.state == _STATE_EXPLOITABLE
            ),
            "vulnerabilities": [
                {
                    "cve_id": e.cve_id,
                    "state": e.state,
                    "cvss": e.cvss,
                    "epss": e.epss,
                    "in_kev": e.in_kev,
                    "severity": e.severity,
                    "affected_paths": list(e.affected_paths),
                }
                for e in self.entries
            ],
        }
