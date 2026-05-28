"""Multi-factor severity scoring: CVSS + EPSS + CISA KEV.

This module enriches binary findings that carry CWE IDs with triage-ready
severity scores drawn from three complementary data sources:

* **NVD API v2** — CVSS base scores linked to representative CVEs for a CWE.
  This sets the *base* triage tier.
* **EPSS (Exploit Prediction Scoring System)** — probability of exploitation
  in the wild, from api.first.org. An EPSS probability at or above
  :attr:`SeverityScore.EPSS_PROMOTE_THRESHOLD` (0.5 — "more likely than not to
  be exploited") promotes the CVSS base tier by one rung, so a moderate-CVSS
  finding that is *likely to be exploited* is triaged ahead of an equally-rated
  finding nobody is exploiting. The promotion is recorded on the score's
  ``epss_promoted`` flag so it stays auditable.
* **CISA KEV catalog** — known-exploited-vulnerabilities list; KEV membership
  (confirmed exploitation in the wild) immediately pins a finding to "critical"
  and cannot be promoted further.

The three sources are combined into a :class:`SeverityScore` dataclass whose
``label`` field mirrors the existing ``severity`` string used elsewhere in the
report (``"info" / "low" / "medium" / "high" / "critical"``).

Cache strategy
--------------
* KEV catalog: fetched once per process and kept in a module-level variable.
  The catalog is ~300 KB; fetching it per-finding would be wasteful.
* EPSS + NVD responses: 24-hour file cache under ``~/.cache/embalmer/`` so
  repeated runs against the same firmware don't hammer the APIs.
* All network calls use a configurable ``timeout`` (default 10 s) with graceful
  fallback on any error — no network access must never crash the pipeline.

Offline / air-gapped use: pass ``enrich=False`` to :func:`score_cwe` or set the
``--no-enrich`` CLI flag. In that mode this module is never imported for I/O.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Optional

# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class SeverityScore:
    """Multi-factor severity score for a single finding.

    Attributes:
        cvss:    CVSS base score (0.0–10.0), or None if unavailable.
        epss:    EPSS probability (0.0–1.0), or None if unavailable.
        in_kev:  True if the canonical CVE is in CISA's KEV catalog.
        label:   Human-readable severity derived from the above.
        cve_id:  The representative CVE used for scoring, if found.
    """

    cvss: Optional[float]
    epss: Optional[float]
    in_kev: bool
    label: str
    cve_id: Optional[str] = field(default=None)
    epss_promoted: bool = field(default=False)

    # EPSS probability at/above which a finding is promoted one triage tier.
    # EPSS estimates the probability a CVE will be exploited in the wild within
    # 30 days; >= 0.5 means "more likely than not to be exploited", the point at
    # which a moderate-CVSS finding deserves to be triaged ahead of an
    # equally-rated finding nobody is exploiting. KEV (confirmed in-the-wild
    # exploitation) still trumps everything and pins to critical directly.
    EPSS_PROMOTE_THRESHOLD: ClassVar[float] = 0.5

    # Ordered triage ladder used by the EPSS one-tier promotion.
    _LADDER: ClassVar[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

    @staticmethod
    def _base_label(cvss: Optional[float], in_kev: bool) -> str:
        """The pre-EPSS label from CVSS score and KEV membership."""
        if in_kev:
            return "critical"
        if cvss is None:
            return "info"
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"

    @classmethod
    def _promote(cls, label: str) -> str:
        """Bump *label* up one rung on the triage ladder (capped at critical)."""
        try:
            idx = cls._LADDER.index(label)
        except ValueError:
            return label
        return cls._LADDER[min(idx + 1, len(cls._LADDER) - 1)]

    @classmethod
    def compute_label(
        cls,
        cvss: Optional[float],
        in_kev: bool,
        epss: Optional[float] = None,
    ) -> str:
        """Derive the severity label from CVSS, KEV membership, and EPSS.

        KEV membership pins to ``critical`` outright (confirmed exploited in the
        wild). Otherwise CVSS sets a base tier (info/low/medium/high/critical),
        and a high EPSS probability — at or above
        :attr:`EPSS_PROMOTE_THRESHOLD` — promotes that base tier by one rung.
        This is the multi-factor triage the Rank 1 roadmap calls for: a
        moderate-CVSS finding that is *likely to be exploited* outranks a
        moderate-CVSS finding that is not. A KEV/critical finding cannot be
        promoted further; a finding with no CVSS data (``info``) is not promoted
        on EPSS alone, since EPSS without a scored CVE is not actionable.
        """
        base = cls._base_label(cvss, in_kev)
        if (
            not in_kev
            and base != "info"
            and base != "critical"
            and epss is not None
            and epss >= cls.EPSS_PROMOTE_THRESHOLD
        ):
            return cls._promote(base)
        return base

    def to_dict(self) -> dict:
        out: dict = {
            "label": self.label,
            "in_kev": self.in_kev,
        }
        if self.cvss is not None:
            out["cvss"] = self.cvss
        if self.epss is not None:
            out["epss"] = self.epss
        if self.epss_promoted:
            # Make the EPSS-driven promotion auditable: an analyst seeing a
            # "high" with a CVSS of only 6.0 should be able to tell it was the
            # exploit-prediction probability, not the base score, that raised it.
            out["epss_promoted"] = True
        if self.cve_id is not None:
            out["cve_id"] = self.cve_id
        return out


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

_CACHE_DIR = Path(os.environ.get("EMBALMER_CACHE_DIR", Path.home() / ".cache" / "embalmer"))
_CACHE_TTL_SECONDS = 86400  # 24 hours


def _cache_path(key: str) -> Path:
    safe = hashlib.sha256(key.encode()).hexdigest()
    return _CACHE_DIR / f"{safe}.json"


def _cache_read(key: str) -> Optional[dict | list]:
    p = _cache_path(key)
    if not p.exists():
        return None
    try:
        stat = p.stat()
        if time.time() - stat.st_mtime > _CACHE_TTL_SECONDS:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _cache_write(key: str, data: dict | list) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(key).write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass  # cache write failure is non-fatal


# ---------------------------------------------------------------------------
# Network fetch (timeout-guarded, graceful on any error)
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT = 10


def _fetch_json(url: str, timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict | list]:
    """GET *url* and return the parsed JSON body, or None on any error."""
    cached = _cache_read(url)
    if cached is not None:
        return cached
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "embalmer/0.1 (firmware-audit)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        _cache_write(url, data)
        return data
    except Exception:
        return None


# ---------------------------------------------------------------------------
# KEV catalog (process-level singleton)
# ---------------------------------------------------------------------------

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: Optional[set[str]] = None


def _get_kev_set(timeout: int = _DEFAULT_TIMEOUT) -> set[str]:
    """Return the set of CVE IDs in the CISA KEV catalog (fetched once per process)."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    data = _fetch_json(_KEV_URL, timeout=timeout)
    if data and isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
        _kev_cache = {v["cveID"] for v in vulns if isinstance(v, dict) and "cveID" in v}
    else:
        _kev_cache = set()
    return _kev_cache


def _reset_kev_cache() -> None:
    """Reset the process-level KEV cache. Used in tests."""
    global _kev_cache
    _kev_cache = None


# ---------------------------------------------------------------------------
# NVD helpers
# ---------------------------------------------------------------------------

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-{cwe_id}"
_NVD_CVE_BY_ID_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def _extract_cvss(cve_item: dict) -> Optional[float]:
    """Extract the highest CVSS base score from a NVD CVE item."""
    metrics = cve_item.get("metrics", {})
    best: Optional[float] = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            try:
                score = float(metric["cvssData"]["baseScore"])
                if best is None or score > best:
                    best = score
            except (KeyError, TypeError, ValueError):
                pass
    return best


def _get_nvd_cves_for_cwe(cwe_id: int, timeout: int = _DEFAULT_TIMEOUT) -> list[dict]:
    """Fetch CVE items from NVD for a given CWE, return parsed list or []."""
    url = _NVD_CVE_URL.format(cwe_id=cwe_id)
    data = _fetch_json(url, timeout=timeout)
    if not data or not isinstance(data, dict):
        return []
    vulns = data.get("vulnerabilities", [])
    return [v.get("cve", {}) for v in vulns if isinstance(v, dict)]


def _get_nvd_cve_by_id(cve_id: str, timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """Fetch a single CVE item by ID from NVD."""
    url = _NVD_CVE_BY_ID_URL.format(cve_id=cve_id)
    data = _fetch_json(url, timeout=timeout)
    if not data or not isinstance(data, dict):
        return None
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return vulns[0].get("cve", {})


# ---------------------------------------------------------------------------
# EPSS helper
# ---------------------------------------------------------------------------

_EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"


def _get_epss(cve_id: str, timeout: int = _DEFAULT_TIMEOUT) -> Optional[float]:
    """Fetch the EPSS probability for a CVE ID; returns None on any error."""
    url = _EPSS_URL.format(cve_id=cve_id)
    data = _fetch_json(url, timeout=timeout)
    if not data or not isinstance(data, dict):
        return None
    items = data.get("data", [])
    if not items:
        return None
    try:
        return float(items[0].get("epss", None))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Public scoring functions
# ---------------------------------------------------------------------------


def score_cve(cve_id: str, timeout: int = _DEFAULT_TIMEOUT) -> SeverityScore:
    """Score a specific CVE using CVSS, EPSS, and KEV.

    Args:
        cve_id: CVE identifier, e.g. ``"CVE-2021-44228"``.
        timeout: HTTP request timeout in seconds.

    Returns:
        A :class:`SeverityScore`. If no data is available for any source the
        corresponding field is None / False and the label falls back to
        ``"info"``.
    """
    cve_item = _get_nvd_cve_by_id(cve_id, timeout=timeout)
    cvss = _extract_cvss(cve_item) if cve_item else None
    epss = _get_epss(cve_id, timeout=timeout)
    kev = _get_kev_set(timeout=timeout)
    in_kev = cve_id in kev
    base = SeverityScore._base_label(cvss, in_kev)
    label = SeverityScore.compute_label(cvss, in_kev, epss)
    return SeverityScore(
        cvss=cvss,
        epss=epss,
        in_kev=in_kev,
        label=label,
        cve_id=cve_id,
        epss_promoted=label != base,
    )


def score_cwe(cwe_id: int, timeout: int = _DEFAULT_TIMEOUT) -> Optional[SeverityScore]:
    """Score a CWE by finding representative CVEs in NVD and taking the max CVSS.

    Fetches CVEs for *cwe_id* from NVD, picks the one with the highest CVSS
    base score, then enriches that CVE with EPSS and KEV data.

    Args:
        cwe_id: Numeric CWE identifier, e.g. ``120`` for CWE-120.
        timeout: HTTP request timeout in seconds.

    Returns:
        A :class:`SeverityScore` based on the worst-case CVE, or ``None`` if
        NVD returns no CVEs for this CWE.
    """
    cve_items = _get_nvd_cves_for_cwe(cwe_id, timeout=timeout)
    if not cve_items:
        return None

    # Pick the CVE with the highest CVSS score as the representative.
    best_cve: Optional[dict] = None
    best_cvss: Optional[float] = None
    for item in cve_items:
        s = _extract_cvss(item)
        if s is not None and (best_cvss is None or s > best_cvss):
            best_cvss = s
            best_cve = item

    # Fallback: if no CVSS scores at all, use the first CVE.
    if best_cve is None and cve_items:
        best_cve = cve_items[0]

    # Extract CVE ID for EPSS + KEV lookup.
    cve_id: Optional[str] = None
    if best_cve:
        cve_id = best_cve.get("id")

    epss: Optional[float] = None
    in_kev = False
    if cve_id:
        epss = _get_epss(cve_id, timeout=timeout)
        kev = _get_kev_set(timeout=timeout)
        in_kev = cve_id in kev

    base = SeverityScore._base_label(best_cvss, in_kev)
    label = SeverityScore.compute_label(best_cvss, in_kev, epss)
    return SeverityScore(
        cvss=best_cvss,
        epss=epss,
        in_kev=in_kev,
        label=label,
        cve_id=cve_id,
        epss_promoted=label != base,
    )
