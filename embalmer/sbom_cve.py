"""NVD CVE cross-referencing of SBOM components.

embalmer *generates* an SBOM inventory (:mod:`embalmer.sbom`) and the Rank 2 /
Rank 8 roadmap's long-standing open item is the other half of that capability:
*cross-reference the identified components against the NVD to surface CVE matches
directly in the SBOM's vulnerability list.* This module is that cross-reference,
implemented **self-contained** — no ossuary dependency.

How it stays self-contained
----------------------------
The Rank 8 framing pinned CVE cross-referencing to ossuary's
known-vulnerable-component database, which is not yet available. But embalmer
already ships a complete, cached, timeout-guarded NVD API v2 client in
:mod:`embalmer.severity` (used today for binary-finding severity scoring), and
the SBOM already carries the one coordinate NVD matches on: a **CPE 2.3** name.
Binary-detected components (statically-linked libraries the ``components`` check
recovers — OpenSSL, BusyBox, …) are merged into the SBOM with their CPE set
(``cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*``). NVD's v2 endpoint accepts a
``cpeName`` query that returns exactly the CVEs applicable to that CPE — so
embalmer can resolve ``OpenSSL 1.0.1f`` to CVE-2014-0160 (Heartbleed) using only
the public NVD API it already speaks.

Why only CPE-bearing components
-------------------------------
NVD matches CVEs by CPE, not by purl. Package-database components
(``dpkg``/``opkg``/``apk``) carry a purl but **no** CPE: a Debian package name is
not an NVD vendor/product pair, and guessing one would produce false matches.
embalmer cross-references only the components it can name with a real CPE (the
binary-detected ones), and leaves the rest un-cross-referenced rather than
overclaiming — the same honest posture the supplier-field enrichment took.

Output shape
------------
The result is attached to the report under ``sbom.vulnerabilities`` as a list of
**CycloneDX 1.6 ``vulnerabilities[]``** objects — the native place a CycloneDX
BOM carries vulnerability data, each with a ``source`` (NVD), a CVSS ``rating``,
a CISA-KEV ``property``, and an ``affects`` reference back to the component's
purl (the bom-ref join downstream tools follow). A quick-look summary
(``cve_count``, ``components_with_cves``) rides alongside.

Network discipline (mirrors :mod:`embalmer.severity`)
-----------------------------------------------------
* All HTTP goes through :func:`embalmer.severity._fetch_json` — 24-hour file
  cache under ``~/.cache/embalmer/`` and a configurable timeout.
* KEV membership reuses :func:`embalmer.severity._get_kev_set` (one fetch per
  process).
* Any network error degrades gracefully to "no CVEs" — cross-referencing must
  never crash the pipeline, and an air-gapped run (or ``--no-enrich``) simply
  produces an empty vulnerability list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import quote

from . import severity

if TYPE_CHECKING:
    from .sbom import Component, Sbom

# NVD API v2: CVEs applicable to a specific CPE 2.3 name. The cpeName query is
# the supported way to ask "what CVEs affect this exact component coordinate?".
_NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"

# Cap the number of CVEs recorded per component. A widely-vulnerable component
# (an ancient OpenSSL) can match dozens of CVEs; the SBOM should surface the most
# severe ones, not become unreadable. CVEs are sorted worst-CVSS-first before the
# cap so the cut keeps the highest-severity matches.
_MAX_CVES_PER_COMPONENT = 25


@dataclass
class CveMatch:
    """One CVE resolved for one SBOM component.

    Distilled from an NVD CVE item plus the CISA KEV catalog into the fields a
    CycloneDX ``vulnerabilities[]`` entry needs. ``purl`` links the CVE back to
    the component it was matched for (the bom-ref join downstream tools follow).
    """

    cve_id: str
    purl: str
    cvss: Optional[float] = None
    severity: str = "info"
    in_kev: bool = False
    description: str = ""
    #: EPSS exploit-prediction probability (0.0–1.0) for this CVE, or None when
    #: EPSS was unavailable (offline, or the CVE has no EPSS score). EPSS is the
    #: third triage factor alongside CVSS and KEV — see :meth:`_match_component`.
    epss: Optional[float] = None
    #: True when a high EPSS probability promoted ``severity`` above the tier the
    #: CVSS base score alone would assign. Kept auditable so an analyst can see a
    #: "high" with a CVSS of only 6.0 was raised by exploit-prediction, not score.
    epss_promoted: bool = False

    def to_cyclonedx(self) -> dict[str, Any]:
        """Render this match as a CycloneDX 1.6 ``vulnerabilities[]`` object."""
        vuln: dict[str, Any] = {
            "id": self.cve_id,
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{self.cve_id}",
            },
        }
        if self.description:
            vuln["description"] = self.description
        if self.cvss is not None:
            vuln["ratings"] = [
                {
                    "source": {"name": "NVD"},
                    "score": self.cvss,
                    "severity": self.severity,
                    "method": "CVSSv31",
                }
            ]
        # KEV and EPSS are exploitability signals, not CVSS ratings — carry them
        # as first-class properties so a consumer can re-derive the verdict.
        properties = [
            {"name": "embalmer:in-kev", "value": "true" if self.in_kev else "false"},
        ]
        if self.epss is not None:
            properties.append(
                {"name": "embalmer:epss", "value": f"{self.epss}"}
            )
        if self.epss_promoted:
            properties.append(
                {"name": "embalmer:epss-promoted", "value": "true"}
            )
        vuln["properties"] = properties
        # `affects` links the CVE back to the component by its purl. CycloneDX
        # `affects[].ref` references a bom-ref; embalmer uses the component's purl
        # (which is also its identity in the BOM) so the linkage is followable.
        vuln["affects"] = [{"ref": self.purl}]
        return vuln

    def to_dict(self) -> dict[str, Any]:
        """The quick-look shape for the report summary."""
        out: dict[str, Any] = {
            "cve_id": self.cve_id,
            "purl": self.purl,
            "cvss": self.cvss,
            "severity": self.severity,
            "in_kev": self.in_kev,
        }
        # Only surface EPSS keys when EPSS actually contributed, keeping the
        # offline / no-EPSS quick-look shape unchanged from prior releases.
        if self.epss is not None:
            out["epss"] = self.epss
        if self.epss_promoted:
            out["epss_promoted"] = True
        return out


@dataclass
class SbomCveReport:
    """The CVE cross-reference report for an SBOM's CPE-bearing components."""

    matches: list[CveMatch] = field(default_factory=list)
    #: Number of SBOM components that carried a CPE and were therefore eligible
    #: for cross-referencing (the denominator for ``components_with_cves``).
    components_checked: int = 0

    @property
    def cve_count(self) -> int:
        return len(self.matches)

    @property
    def components_with_cves(self) -> int:
        return len({m.purl for m in self.matches})

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "NVD (services.nvd.nist.gov, CPE-name cross-reference)",
            "components_checked": self.components_checked,
            "components_with_cves": self.components_with_cves,
            "cve_count": self.cve_count,
            "vulnerabilities": [m.to_dict() for m in self.matches],
            # The full CycloneDX vulnerabilities[] array, the native BOM carrier.
            "bom": [m.to_cyclonedx() for m in self.matches],
        }


def _description(cve_item: dict) -> str:
    """The English description from an NVD CVE item, or ``""``."""
    for d in cve_item.get("descriptions", []):
        if isinstance(d, dict) and d.get("lang") == "en":
            text = d.get("value", "")
            if isinstance(text, str):
                return text
    return ""


def _cves_for_cpe(cpe: str, timeout: int) -> list[dict]:
    """Fetch the NVD CVE items applicable to a CPE 2.3 name (or [] on error)."""
    url = _NVD_CPE_URL.format(cpe=quote(cpe, safe=""))
    data = severity._fetch_json(url, timeout=timeout)
    if not data or not isinstance(data, dict):
        return []
    vulns = data.get("vulnerabilities", [])
    return [v.get("cve", {}) for v in vulns if isinstance(v, dict) and v.get("cve")]


def _match_component(
    component: "Component",
    timeout: int,
    kev: set[str],
    epss_threshold: Optional[float] = None,
) -> list[CveMatch]:
    """Resolve the NVD CVEs for one CPE-bearing component into CveMatches.

    Returns ``[]`` for a component with no CPE (nothing to query NVD with) or
    when NVD returns nothing. Matches are sorted worst-CVSS-first and capped at
    :data:`_MAX_CVES_PER_COMPONENT` so a widely-vulnerable component surfaces its
    most severe CVEs without flooding the BOM.

    Each matched CVE is enriched with its EPSS exploit-prediction probability
    (one FIRST.org lookup per CVE, cached and timeout-guarded via
    :func:`embalmer.severity._get_epss`), and the severity label is the
    multi-factor verdict from :meth:`embalmer.severity.SeverityScore.compute_label`
    — KEV/CVSS as before, plus an EPSS promotion when a CVE's exploit-prediction
    probability is at or above ``epss_threshold``. This is the same triage the
    binary-finding path applies, so a CVE reaches the same label whether it was
    surfaced from a CWE-detected binary finding or an SBOM CPE cross-reference.
    EPSS is best-effort: any lookup that fails leaves ``epss`` None and falls
    back to the KEV/CVSS-only label, so an offline run degrades cleanly.

    To bound EPSS network cost on a widely-vulnerable component (an ancient
    OpenSSL can match dozens of CVEs), the worst-CVSS-first sort and the
    :data:`_MAX_CVES_PER_COMPONENT` cap are applied *before* the EPSS lookups —
    EPSS is fetched only for the CVEs that will actually appear in the BOM.
    """
    cpe = component.cpe
    if not cpe:
        return []
    purl = component.purl()
    items = _cves_for_cpe(cpe, timeout=timeout)
    matches: list[CveMatch] = []
    seen: set[str] = set()
    for item in items:
        cve_id = item.get("id")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        cvss = severity._extract_cvss(item)
        in_kev = cve_id in kev
        # Base (KEV/CVSS-only) label now; EPSS promotion is layered on after the
        # cap, once EPSS has been fetched only for the CVEs that survive.
        base = severity.SeverityScore._base_label(cvss, in_kev)
        matches.append(
            CveMatch(
                cve_id=cve_id,
                purl=purl,
                cvss=cvss,
                severity=base,
                in_kev=in_kev,
                description=_description(item),
            )
        )
    # Worst-CVSS-first (None last), then CVE id for stable order, then cap. The
    # cap runs before EPSS lookups so we never fetch EPSS for a CVE the cap drops.
    matches.sort(key=lambda m: (-(m.cvss if m.cvss is not None else -1.0), m.cve_id))
    matches = matches[:_MAX_CVES_PER_COMPONENT]
    for m in matches:
        epss = severity._get_epss(m.cve_id, timeout=timeout)
        if epss is None:
            continue
        m.epss = epss
        promoted = severity.SeverityScore.compute_label(
            m.cvss, m.in_kev, epss, epss_threshold
        )
        if promoted != m.severity:
            m.severity = promoted
            m.epss_promoted = True
    return matches


def cross_reference(
    sbom: "Sbom", timeout: int = 10, epss_threshold: Optional[float] = None
) -> SbomCveReport:
    """Cross-reference an SBOM's CPE-bearing components against the NVD.

    Iterates the SBOM components, and for each one that carries a CPE 2.3 name
    (the binary-detected components — package-database components have no CPE and
    are skipped), queries NVD for the CVEs applicable to that CPE and records
    them as :class:`CveMatch` entries. Each match is then enriched with KEV
    membership (CISA catalog) and its EPSS exploit-prediction probability
    (FIRST.org), and its severity label is the multi-factor verdict — CVSS base
    tier, KEV pin-to-critical, and EPSS promotion at or above ``epss_threshold``
    — identical to the triage the binary-finding path applies. Every network
    call is cached and timeout-guarded and degrades gracefully (a missing EPSS
    score falls back to the KEV/CVSS-only label; a fully offline run produces an
    empty report), so the cross-reference is safe to run in the pipeline.

    Args:
        epss_threshold: EPSS promotion cut-off (an EPSS at or above it bumps the
            label one rung). ``None`` uses
            :attr:`embalmer.severity.SeverityScore.EPSS_PROMOTE_THRESHOLD`. A
            threshold above 1.0 disables the EPSS factor (EPSS is 0.0–1.0).

    Components are visited in SBOM order; within a component, CVEs are
    worst-CVSS-first and capped, so the output is deterministic for a given NVD
    response.
    """
    report = SbomCveReport()
    eligible = [c for c in sbom.components if c.cpe]
    report.components_checked = len(eligible)
    if not eligible:
        return report
    kev = severity._get_kev_set(timeout=timeout)
    for component in eligible:
        report.matches.extend(
            _match_component(
                component, timeout=timeout, kev=kev, epss_threshold=epss_threshold
            )
        )
    return report
