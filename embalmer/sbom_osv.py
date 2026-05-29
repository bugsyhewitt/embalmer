"""OSV.dev CVE cross-referencing of package-database SBOM components.

The companion to :mod:`embalmer.sbom_cve`. Where ``sbom_cve`` resolves
**CPE-bearing** (binary-detected) SBOM components against the NVD,
``sbom_osv`` resolves the **package-database** components (``dpkg`` / ``opkg`` /
``apk``) — the ones :mod:`sbom_cve` deliberately skips because NVD matches on
CPE, not purl, and a Debian package name is not an NVD vendor/product pair.

Why OSV
--------
[OSV.dev](https://osv.dev/) is the canonical **purl-keyed** public vulnerability
database — run by Google, the backend OSV-Scanner, Dependabot, and most modern
SCA tools join on. Its ``/v1/query`` endpoint accepts a component identified by
its purl (``pkg:deb/...``, ``pkg:apk/...``) and returns the OSV vulnerability
records applicable to it. OSV records carry a CVE id (or a list of CVE aliases),
a severity score (CVSS v3 vector), and a free-text summary — exactly the
fields embalmer's CVE cross-reference shape (:class:`embalmer.sbom_cve.CveMatch`)
already carries. So the package-DB half of the SBOM cross-reference closes
with no schema change downstream: matched CVEs flow into the **same**
``sbom.vulnerabilities`` CycloneDX vulnerabilities[] array, just sourced from a
different upstream.

Why two upstreams, not one
--------------------------
NVD's CPE index covers projects (``cpe:2.3:a:openssl:openssl:1.0.1f``);
OSV's purl index covers package coordinates (``pkg:deb/bash@5.0-4``). Neither
covers the other half cleanly:

* an NVD ``cpeName`` query on a Debian package name returns nothing,
* an OSV ``purl`` query on a binary-detected ``pkg:generic/openssl@1.0.1f``
  returns nothing — OSV indexes the *package ecosystems* (Debian, Alpine, PyPI,
  …), not the generic-purl namespace.

So embalmer queries the upstream that *can* answer for each component class:
NVD for the binary-detected (CPE-bearing) components,
OSV for the package-database components. The two paths produce CycloneDX
``vulnerabilities[]`` entries of the same shape under the same
``sbom.vulnerabilities`` key, deduplicated by ``(cve_id, purl)`` so a CVE that
happens to match a component via both paths surfaces once. Honest posture
preserved: each component is cross-referenced exactly once, against the
upstream that names it.

Network discipline
------------------
* All HTTP goes through :func:`_osv_query` — a POST helper mirroring
  :func:`embalmer.severity._fetch_json`'s 24-hour file cache and timeout. POST
  bodies are part of the cache key, so different purls cache independently.
* KEV membership reuses :func:`embalmer.severity._get_kev_set` (one fetch per
  process).
* Any network error degrades gracefully to "no CVEs" — cross-referencing must
  never crash the pipeline, and an air-gapped run (or ``--no-enrich``) simply
  produces an empty vulnerability list.
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import TYPE_CHECKING, Optional

from . import severity
from .sbom_cve import CveMatch, SbomCveReport

if TYPE_CHECKING:
    from .sbom import Component, Sbom

# OSV.dev v1 query endpoint. Accepts a JSON body of
# ``{"package": {"purl": "<purl>"}}`` (or a ``commit`` / ``version`` form,
# unused here) and returns ``{"vulns": [<OSV record>, ...]}``.
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Cap the number of CVEs recorded per component. A widely-vulnerable package
# version (an unpatched bash) can match dozens of CVEs; the SBOM should surface
# the most severe ones, not become unreadable. CVEs are sorted worst-CVSS-first
# before the cap so the cut keeps the highest-severity matches. Matches the
# :data:`embalmer.sbom_cve._MAX_CVES_PER_COMPONENT` ceiling for consistency.
_MAX_CVES_PER_COMPONENT = 25

# CVE id pattern — the OSV record's ``id`` is sometimes an OSV/GHSA/distro id and
# its CVE alias lives in ``aliases``. The cross-reference surfaces CVEs (the
# universal vuln identifier), so we filter to CVE-shaped ids.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# OSV severity vectors. OSV records carry zero or more ``severity[]`` entries,
# each with a ``type`` (``CVSS_V2``/``CVSS_V3``/``CVSS_V4``) and a vector string
# (``CVSS:3.1/AV:N/...``). The base score is encoded in the vector — but OSV
# also commonly carries a ``database_specific.cvss.score`` numeric. We try the
# numeric form first (no CVSS-vector parser needed), then fall back to parsing
# the ``baseScore`` out of the vector string if present.
_CVSS_BASE_SCORE_RE = re.compile(r"\bbaseScore[:=]\s*(\d+(?:\.\d+)?)", re.IGNORECASE)


def _extract_osv_cvss(record: dict) -> Optional[float]:
    """Pull a CVSS base score (0.0–10.0) from one OSV record, or None.

    OSV records expose CVSS in several places depending on the upstream feed.
    Try them in worst-case-first order: an explicit numeric ``score`` first,
    then a parsed ``baseScore`` out of a CVSS vector. The cross-CVSS-version
    worst-case is naturally taken because the caller iterates every
    ``severity`` entry and keeps the max.
    """
    best: Optional[float] = None
    for sev in record.get("severity", []) or ():
        if not isinstance(sev, dict):
            continue
        # OSV mainly carries the CVSS *vector* in the ``score`` field, but some
        # entries put a raw base score there. Accept either: try numeric first.
        score = sev.get("score")
        candidate: Optional[float] = None
        if isinstance(score, (int, float)):
            candidate = float(score)
        elif isinstance(score, str):
            # CVSS vectors don't carry a baseScore segment, so a numeric-looking
            # string is the raw score; a vector string requires upstream parsing
            # we don't take on (a real CVSS parser is non-trivial). The OSV
            # ``database_specific`` path below catches the common case where the
            # source feed already computed the score.
            try:
                candidate = float(score)
            except ValueError:
                m = _CVSS_BASE_SCORE_RE.search(score)
                if m:
                    candidate = float(m.group(1))
        if candidate is not None and (best is None or candidate > best):
            best = candidate
    # ``database_specific.cvss.score`` is the per-source fallback OSV feeds
    # often carry (the source already computed it).
    db = record.get("database_specific")
    if isinstance(db, dict):
        cvss = db.get("cvss")
        if isinstance(cvss, dict):
            s = cvss.get("score")
            if isinstance(s, (int, float)):
                candidate = float(s)
                if best is None or candidate > best:
                    best = candidate
    return best


def _cve_ids(record: dict) -> list[str]:
    """Return every CVE id this OSV record exposes (id + aliases, deduped)."""
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (record.get("id"), *(record.get("aliases") or ())):
        if not isinstance(candidate, str):
            continue
        if not _CVE_RE.match(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def _summary(record: dict) -> str:
    """Human-readable summary from an OSV record, preferring ``summary``."""
    summary = record.get("summary")
    if isinstance(summary, str) and summary:
        return summary
    details = record.get("details")
    if isinstance(details, str) and details:
        # ``details`` can be long markdown; the description field downstream is a
        # short summary, so take the first sentence/line only.
        first = details.split("\n", 1)[0].strip()
        return first[:500]
    return ""


def _cache_key(purl: str) -> str:
    """Cache key for an OSV purl query — POST URLs would collide otherwise."""
    return f"osv:purl:{purl}"


def _osv_query(purl: str, timeout: int) -> list[dict]:
    """POST one OSV purl query and return ``vulns[]`` (cached, fail-safe).

    Cache and discipline mirror :func:`embalmer.severity._fetch_json` — 24h file
    cache keyed on the purl (since POST URLs are identical), any error returns
    ``[]`` rather than raising so the pipeline keeps running.
    """
    # We piggy-back on the severity cache layer by using its file format. The
    # cache key is the literal purl-query string (not the URL), so different
    # purls cache independently.
    key = _cache_key(purl)
    cached = severity._cache_read(key)
    if cached is not None:
        # Cached body is the parsed ``vulns[]`` list.
        return cached if isinstance(cached, list) else []
    body = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    try:
        req = urllib.request.Request(
            _OSV_QUERY_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "embalmer/0.1 (firmware-audit)",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulns", [])
    if not isinstance(vulns, list):
        return []
    # Cache the distilled list, not the whole envelope — both are valid JSON.
    severity._cache_write(key, vulns)
    return vulns


def _match_component(
    component: "Component",
    timeout: int,
    kev: set[str],
    epss_threshold: Optional[float] = None,
) -> list[CveMatch]:
    """Resolve OSV vulnerabilities for one package-database component.

    Returns ``[]`` for a component that is not a package-database one
    (binary-detected components are handled by :mod:`embalmer.sbom_cve` against
    NVD's CPE index instead). For each OSV record returned, every CVE alias
    becomes one :class:`CveMatch` — so an OSV record with two CVE aliases
    surfaces two CVEs in the BOM, each carrying the OSV-asserted CVSS score and
    summary.

    Matches are sorted worst-CVSS-first and capped at
    :data:`_MAX_CVES_PER_COMPONENT`. EPSS is fetched only for the CVEs that
    survive the cap (one FIRST.org lookup per CVE, cached and timeout-guarded
    via :func:`embalmer.severity._get_epss`), matching the
    :func:`embalmer.sbom_cve._match_component` pattern so the two cross-reference
    paths produce semantically identical entries.
    """
    if component.source not in ("dpkg", "opkg", "apk"):
        return []
    purl = component.purl()
    records = _osv_query(purl, timeout=timeout)
    matches: list[CveMatch] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        cvss = _extract_osv_cvss(record)
        summary = _summary(record)
        for cve_id in _cve_ids(record):
            if cve_id in seen:
                continue
            seen.add(cve_id)
            in_kev = cve_id in kev
            base = severity.SeverityScore._base_label(cvss, in_kev)
            matches.append(
                CveMatch(
                    cve_id=cve_id,
                    purl=purl,
                    cvss=cvss,
                    severity=base,
                    in_kev=in_kev,
                    description=summary,
                )
            )
    # Worst-CVSS-first (None last), then CVE id for stable order, then cap.
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
    sbom: "Sbom",
    timeout: int = 10,
    epss_threshold: Optional[float] = None,
    existing: Optional[SbomCveReport] = None,
) -> SbomCveReport:
    """Cross-reference an SBOM's package-database components against OSV.dev.

    The package-DB half of the cross-reference (``dpkg``/``opkg``/``apk``
    components), complementary to :func:`embalmer.sbom_cve.cross_reference`'s
    CPE-bearing half. Output is a :class:`SbomCveReport` of the **same shape**
    as the NVD cross-reference — the two halves are merged into one
    ``sbom.vulnerabilities`` section downstream, so a consumer reads a single
    unified CVE list regardless of which upstream resolved which component.

    Args:
        existing: When supplied, OSV matches are *merged* into this prior NVD
            report rather than returning a fresh one, with
            ``(cve_id, purl)``-keyed deduplication. The merged report is
            returned. This is how the pipeline produces one unified
            ``sbom.vulnerabilities`` section from the two upstreams.
        epss_threshold: EPSS promotion cut-off. ``None`` uses
            :attr:`embalmer.severity.SeverityScore.EPSS_PROMOTE_THRESHOLD`. A
            threshold above 1.0 disables the EPSS factor.

    Components are visited in SBOM order; within a component, CVEs are
    worst-CVSS-first and capped, so the output is deterministic for a given
    OSV response.
    """
    report = existing if existing is not None else SbomCveReport(sources=())
    # Tag the OSV upstream onto the merged report exactly once, so the
    # ``source`` field reflects which upstreams contributed (NVD-only / OSV-only
    # / NVD+OSV). Appending only when absent keeps idempotency.
    if "OSV" not in report.sources:
        report.sources = report.sources + ("OSV",)
    eligible = [c for c in sbom.components if c.source in ("dpkg", "opkg", "apk")]
    report.components_checked += len(eligible)
    if not eligible:
        return report
    kev = severity._get_kev_set(timeout=timeout)
    # Dedup key: (CVE id, purl) — the same CVE on two purls is two different
    # affects, so it stays as two entries; the same CVE on one purl from two
    # upstreams is one entry. Build the seen set from the existing matches so
    # NVD entries already carrying a CVE on a purl are not duplicated.
    seen: set[tuple[str, str]] = {(m.cve_id, m.purl) for m in report.matches}
    for component in eligible:
        for match in _match_component(
            component, timeout=timeout, kev=kev, epss_threshold=epss_threshold
        ):
            key = (match.cve_id, match.purl)
            if key in seen:
                continue
            seen.add(key)
            report.matches.append(match)
    return report
