"""SBOM component vulnerability-age check.

Firmware images are often shipped once and forgotten — the same binary
persists for years on IoT devices with no over-the-air update.  Security
researchers and vendors keep publishing new CVEs, advisories, and exploit
proof-of-concepts against the libraries those images ship, but the firmware
owner has no easy signal that the threat landscape for *their specific
component versions* changed since their last audit.

This module answers the question:

    *"Which components in this firmware have had their OSV vulnerability
    records updated recently?"*

A recently-modified OSV record means one of the following happened:

* A new CVE was assigned against the component version.
* An existing CVE was re-scored (often upward, after active exploitation).
* A previously-disputed CVE was confirmed.
* A PoC exploit was published, updating the KEV or EPSS picture.
* The OSV record was updated with new fix or affected-version information.

Any of these is a signal that a security team should re-audit the
firmware for that component, even if they ran a clean scan last month.

How it works
------------

For each **package-database** component (``dpkg``/``opkg``/``apk``) in the
SBOM the module re-uses the same :func:`embalmer.sbom_osv._osv_query`
helper (and its 24-hour file cache) to retrieve the OSV vulnerability
records applicable to the component's purl.  From each record it extracts
the ``modified`` timestamp — the RFC-3339 UTC datetime OSV last updated
the record.  The most-recent ``modified`` value across all CVEs for that
component becomes the component's *vuln record age*: the time elapsed since
any vulnerability affecting that version was touched.

A new ``--sbom-age-check [DAYS]`` flag (default **90 days**) marks any
component whose vuln record age is *less than* DAYS as **recently active**.
Components with no applicable CVEs at all are recorded as ``no_vulns`` —
the check does not claim they are safe, it simply has no age signal.
Components with CVEs but no ``modified`` timestamp (rare edge-case in older
OSV records) are flagged as ``unknown_age`` so the consumer can decide.

The verdict rides under a new ``sbom.vuln_age`` report key as a structured
per-component report — overall ``has_recent_activity`` boolean, the
threshold in days, and the per-component result with the most-recent
modified date and the most recently modified CVE id.  The report is sorted
worst-first (most recently modified first) so the CI log reads like a
priority list.

Honest posture
--------------

* The check is scoped to package-database components only (the same scope
  as ``--sbom-osv``): binary-detected components use the NVD CPE path, and
  the NVD API does not expose a per-record ``modified`` timestamp in a
  queryable form; an OSV purl query against ``pkg:generic/openssl@1.0.1f``
  returns no results because OSV indexes package ecosystems, not generic
  purls.
* A component with no applicable CVEs is **not** reported as safe — it is
  reported as ``no_vulns``, reflecting that OSV found nothing *for that
  purl*; the binary-detected components next to it may still carry NVD CVEs
  that the ``--sbom-cve`` check surfaces.
* The 24-hour cache means a CI loop that runs embalmer daily will see fresh
  OSV ``modified`` timestamps at most once per day, not once per run.
  ``--no-enrich`` skips the check entirely (the age data requires network
  access).

Self-contained: reuses :func:`embalmer.sbom_osv._osv_query` (and its cache)
and :func:`embalmer.sbom_osv._cve_ids` — no new network primitives.  Off
by default — every existing report path is byte-for-byte unchanged.
Composes with ``--fail-on``: each recently-active component is scored at
``medium`` severity so ``--sbom-age-check --fail-on medium`` fails CI with
exit code 10 when any firmware component's CVE landscape changed in the
last N days.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from . import sbom_osv  # for _osv_query, _cve_ids (same cache, same primitives)

if TYPE_CHECKING:
    from .sbom import Sbom

# Severity assigned to a recently-active component for the ``--fail-on``
# gate.  ``medium`` is the right tier: knowing a CVE record was recently
# modified is an *alert*, not a confirmed exploit — the analyst still needs
# to assess the change.  It sits on the same rung as a non-KEV/low-EPSS
# CVE from the NVD cross-reference.
RECENT_ACTIVITY_SEVERITY = "medium"

#: Default freshness window in days.  OSV records modified within this
#: window are flagged as recently active.
DEFAULT_AGE_DAYS = 90

# RFC-3339 / ISO-8601 UTC timestamp pattern from OSV records.
# Matches ``2024-11-14T20:37:07Z`` and ``2024-11-14T20:37:07.000000Z``.
_TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$"
)


def _parse_modified(ts: Any) -> Optional[datetime.datetime]:
    """Parse an OSV ``modified`` string to a UTC-aware datetime, or None."""
    if not isinstance(ts, str):
        return None
    m = _TS_RE.match(ts)
    if not m:
        return None
    try:
        return datetime.datetime(
            int(m.group(1)),
            int(m.group(2)),
            int(m.group(3)),
            int(m.group(4)),
            int(m.group(5)),
            int(m.group(6)),
            tzinfo=datetime.timezone.utc,
        )
    except ValueError:
        return None


def _most_recent_modified(records: list[dict]) -> tuple[Optional[datetime.datetime], Optional[str]]:
    """Return the (most-recent modified datetime, cve_id) across all records.

    The second element is the CVE id of the record that carried the most
    recent ``modified`` timestamp, or ``None`` when no CVE id was found on
    that record (rare edge-case for non-CVE OSV records).
    """
    best_dt: Optional[datetime.datetime] = None
    best_cve: Optional[str] = None
    for record in records:
        if not isinstance(record, dict):
            continue
        dt = _parse_modified(record.get("modified"))
        if dt is None:
            continue
        if best_dt is None or dt > best_dt:
            best_dt = dt
            # Prefer the first CVE alias on this record as the attribution.
            cve_ids = sbom_osv._cve_ids(record)
            best_cve = cve_ids[0] if cve_ids else None
    return best_dt, best_cve


@dataclass
class AgedComponent:
    """Per-component vulnerability-record age verdict."""

    purl: str
    name: str
    version: str
    #: Status bucket:
    #:
    #: ``"recent"``      — has CVEs with a ``modified`` timestamp within the
    #:                     freshness window; the component should be re-audited.
    #: ``"older"``       — has CVEs but none were modified within the window.
    #: ``"unknown_age"`` — has CVEs but none carried a parseable ``modified``
    #:                     timestamp (edge-case in old OSV records).
    #: ``"no_vulns"``    — no applicable CVEs found in OSV for this purl.
    status: str
    #: Most-recent ``modified`` datetime across all CVEs for this component,
    #: in ISO-8601 UTC format.  ``None`` when ``status`` is ``"no_vulns"`` or
    #: ``"unknown_age"``.
    most_recent_modified: Optional[str] = None
    #: CVE id of the most recently modified record.  ``None`` when not
    #: applicable (status is ``"no_vulns"`` or ``"unknown_age"``).
    most_recent_cve: Optional[str] = None
    #: Days elapsed since the most recently modified CVE record, computed at
    #: check time.  ``None`` when no ``modified`` timestamp is available.
    days_since_modified: Optional[int] = None

    @property
    def is_recently_active(self) -> bool:
        """Whether this component should be flagged by the age gate."""
        return self.status == "recent"

    @property
    def severity(self) -> Optional[str]:
        """Severity tier for the ``--fail-on`` gate.

        Recently-active components are scored at
        :data:`RECENT_ACTIVITY_SEVERITY`; all other statuses contribute no
        severity (they are informational or neutral).
        """
        return RECENT_ACTIVITY_SEVERITY if self.is_recently_active else None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "purl": self.purl,
            "name": self.name,
            "version": self.version,
            "status": self.status,
        }
        if self.most_recent_modified is not None:
            out["most_recent_modified"] = self.most_recent_modified
        if self.most_recent_cve is not None:
            out["most_recent_cve"] = self.most_recent_cve
        if self.days_since_modified is not None:
            out["days_since_modified"] = self.days_since_modified
        if self.is_recently_active:
            out["severity"] = RECENT_ACTIVITY_SEVERITY
        return out


@dataclass
class SbomAgeReport:
    """SBOM component vulnerability-age check report."""

    #: Freshness threshold in days.  Components with CVE records modified
    #: within this window are considered recently active.
    threshold_days: int
    #: Whether any component was flagged as recently active.
    has_recent_activity: bool
    #: Per-component verdicts, sorted most-recently-modified first (then
    #: alphabetically by purl for stable ties).
    components: list[AgedComponent] = field(default_factory=list)

    @property
    def recent_count(self) -> int:
        """Number of components with recently-active CVE records."""
        return sum(1 for c in self.components if c.is_recently_active)

    @property
    def no_vulns_count(self) -> int:
        """Number of components with no applicable CVEs in OSV."""
        return sum(1 for c in self.components if c.status == "no_vulns")

    @property
    def older_count(self) -> int:
        """Number of components with CVEs but none modified within the window."""
        return sum(1 for c in self.components if c.status == "older")

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold_days": self.threshold_days,
            "has_recent_activity": self.has_recent_activity,
            "recent_count": self.recent_count,
            "older_count": self.older_count,
            "no_vulns_count": self.no_vulns_count,
            "component_count": len(self.components),
            "components": [c.to_dict() for c in self.components],
        }


def check(
    sbom: "Sbom",
    threshold_days: int = DEFAULT_AGE_DAYS,
    timeout: int = 10,
) -> SbomAgeReport:
    """Check the SBOM's package-database components for recent CVE activity.

    For each ``dpkg``/``opkg``/``apk`` component, queries OSV.dev (reusing the
    same 24-hour file cache as ``--sbom-osv``) and extracts the most-recent
    ``modified`` timestamp across all returned vulnerability records.  Components
    whose most-recent ``modified`` date falls within ``threshold_days`` of
    *today* are flagged as recently active.

    Args:
        sbom: The :class:`~embalmer.sbom.Sbom` inventory to check.
        threshold_days: Freshness window in days (default 90).  OSV records
            modified within this many days of today are flagged.
        timeout: Per-request HTTP timeout in seconds.  Passed through to
            :func:`embalmer.sbom_osv._osv_query`.

    Returns:
        A :class:`SbomAgeReport` with per-component verdicts.
    """
    eligible = [c for c in sbom.components if c.source in ("dpkg", "opkg", "apk")]
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=threshold_days)

    verdicts: list[AgedComponent] = []
    for comp in eligible:
        purl = comp.purl()
        records = sbom_osv._osv_query(purl, timeout=timeout)

        if not records:
            verdicts.append(
                AgedComponent(
                    purl=purl,
                    name=comp.name,
                    version=comp.version,
                    status="no_vulns",
                )
            )
            continue

        best_dt, best_cve = _most_recent_modified(records)

        if best_dt is None:
            # CVEs found but no parseable modified timestamp.
            verdicts.append(
                AgedComponent(
                    purl=purl,
                    name=comp.name,
                    version=comp.version,
                    status="unknown_age",
                )
            )
            continue

        days_ago = int((now - best_dt).total_seconds() // 86400)
        status = "recent" if best_dt >= cutoff else "older"
        verdicts.append(
            AgedComponent(
                purl=purl,
                name=comp.name,
                version=comp.version,
                status=status,
                most_recent_modified=best_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                most_recent_cve=best_cve,
                days_since_modified=days_ago,
            )
        )

    # Sort: recently-active first (most recently modified first within that
    # group), then older, then unknown_age, then no_vulns; stable by purl
    # within each group.
    def _sort_key(c: AgedComponent) -> tuple:
        order = {"recent": 0, "older": 1, "unknown_age": 2, "no_vulns": 3}
        rank = order.get(c.status, 99)
        # For recent/older, sort by days_since_modified ascending (most recent
        # first = smallest number of days = smallest key).
        age = c.days_since_modified if c.days_since_modified is not None else 9999999
        return (rank, age, c.purl)

    verdicts.sort(key=_sort_key)

    has_recent = any(v.is_recently_active for v in verdicts)
    return SbomAgeReport(
        threshold_days=threshold_days,
        has_recent_activity=has_recent,
        components=verdicts,
    )
