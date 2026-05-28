"""Software Bill of Materials (SBOM) generation.

Walks an extracted firmware filesystem's package-manager databases and emits a
CycloneDX 1.6 JSON SBOM describing every installed package as a component.

Three package-manager families cover the overwhelming majority of Linux-based
firmware images:

    - dpkg   (Debian/Ubuntu)  -> /var/lib/dpkg/status
    - opkg   (OpenWrt)        -> /var/lib/opkg/info/*.control and
                                 /usr/lib/opkg/status, /etc/opkg/status
    - apk    (Alpine)         -> /lib/apk/db/installed

All three store package metadata in a deb822-style "stanza" format: groups of
``Field: value`` lines separated by blank lines, one stanza per package. apk's
``installed`` database uses single-letter keys (``P``, ``V``, ``A``, ``T``,
``L``, ``c``) but the same blank-line-separated-stanza structure, so a single
generic stanza parser handles all three with per-format key maps.

Like the rest of embalmer this is deliberately forgiving: a malformed stanza is
skipped rather than aborting the whole scan, and a database that does not exist
simply contributes no components. The goal is an inventory, not a validator.

The emitted SBOM is a plain ``dict`` matching the CycloneDX 1.6 JSON schema
(ECMA-424). It is attached to the report under the ``sbom`` key and is also
serialized verbatim — embalmer does not invent its own component shape, it
emits the industry-standard one so the artifact drops straight into any
CycloneDX-aware consumer (Dependency-Track, grype, trivy, etc.).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

if TYPE_CHECKING:
    from .models import Finding

# CycloneDX spec version emitted. 1.6 is the current ECMA-424 release and adds
# the IoT/hardware BOM and native VEX support called out in POST_V01.md.
CYCLONEDX_SPEC_VERSION = "1.6"

# Don't try to read multi-megabyte blobs as package databases.
_MAX_READ_BYTES = 50_000_000


@dataclass
class Component:
    """A single installed package, normalized across package managers.

    Most components come from a package-manager database (``source`` of
    ``"dpkg"``/``"opkg"``/``"apk"``). A component may instead be recovered from a
    *binary's* baked-in version string (``source="binary"``) — these are the
    statically-linked third-party libraries (OpenSSL, BusyBox, …) that no package
    database lists. Binary-sourced components carry a ``cpe`` (set by the
    ``components`` check) instead of a package-manager ``db_path``, and their
    ``db_path`` records the binary the version banner came from.
    """

    name: str
    version: str
    # One of: "dpkg", "opkg", "apk" — the database the component came from — or
    # "binary" for a component recovered from a binary's baked-in version string.
    source: str
    architecture: str | None = None
    description: str | None = None
    license_id: str | None = None
    # Relative path (under the extract root) of the database file this came from,
    # or — for a "binary"-sourced component — the binary the version banner was
    # recovered from.
    db_path: str = ""
    # CPE 2.3 identifier, set for "binary"-sourced components (the coordinate
    # ossuary/NVD key on). ``None`` for package-database components, which are
    # identified by their purl instead.
    cpe: str | None = None

    @classmethod
    def from_component_finding(cls, finding: "Finding") -> "Component | None":
        """Build a binary-sourced Component from a ``components`` check Finding.

        Returns ``None`` if the finding does not carry the component/version
        metadata the ``components`` check populates (e.g. an unrelated finding),
        so the caller can merge defensively.
        """
        extra = finding.extra
        name = extra.get("component")
        version = extra.get("version")
        if not name or not version:
            return None
        return cls(
            name=name,
            version=version,
            source="binary",
            db_path=finding.path,
            cpe=extra.get("cpe"),
        )

    def purl(self) -> str:
        """A Package URL (purl) identifying this component.

        purls are the CycloneDX-recommended component identifier and the key
        downstream tools use to match against vulnerability databases. The
        ``type`` namespace maps the package manager:

            dpkg -> pkg:deb     opkg -> pkg:opkg     apk -> pkg:apk

        A binary-sourced component is not package-managed, so it uses the
        ``pkg:generic`` namespace (the purl spec's catch-all for a component
        with no native package manager).
        """
        purl_type = {
            "dpkg": "deb",
            "opkg": "opkg",
            "apk": "apk",
            "binary": "generic",
        }.get(self.source, self.source)
        base = f"pkg:{purl_type}/{quote(self.name, safe='')}@{quote(self.version, safe='')}"
        if self.architecture:
            base += f"?arch={quote(self.architecture, safe='')}"
        return base

    def to_cyclonedx(self) -> dict[str, Any]:
        """Render this component as a CycloneDX 1.6 component object."""
        properties: list[dict[str, str]] = [
            {"name": "embalmer:package-manager", "value": self.source},
        ]
        if self.source == "binary":
            properties = [{"name": "embalmer:detected-from", "value": "binary-strings"}]
            if self.db_path:
                properties.append({"name": "embalmer:binary", "value": self.db_path})
        elif self.db_path:
            properties.append({"name": "embalmer:database", "value": self.db_path})
        comp: dict[str, Any] = {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl(),
            "properties": properties,
        }
        # CPE is the coordinate ossuary/NVD resolve to CVEs; CycloneDX has a
        # first-class `cpe` field for exactly this, so emit it when known.
        if self.cpe:
            comp["cpe"] = self.cpe
        if self.description:
            comp["description"] = self.description
        if self.license_id:
            comp["licenses"] = [{"license": {"name": self.license_id}}]
        return comp


@dataclass
class Sbom:
    """The result of an SBOM scan: a list of components plus the BOM document."""

    components: list[Component] = field(default_factory=list)

    def to_cyclonedx(
        self, firmware: str, timestamp: datetime.datetime | None = None
    ) -> dict[str, Any]:
        """Render a complete CycloneDX 1.6 BOM document.

        ``firmware`` names the subject of the BOM (recorded as the root
        ``metadata.component``). ``timestamp`` defaults to now (UTC).
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
            "components": [c.to_cyclonedx() for c in self.components],
        }

    def to_dict(self) -> dict[str, Any]:
        """The shape attached to the embalmer report.

        ``component_count`` is a convenience field for the markdown renderer and
        for quick programmatic checks; ``components`` is the per-package summary
        and ``bom`` is the full CycloneDX document for export.
        """
        return {
            "component_count": len(self.components),
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "source": c.source,
                    "architecture": c.architecture,
                    "purl": c.purl(),
                    "db_path": c.db_path,
                    "cpe": c.cpe,
                }
                for c in self.components
            ],
        }

    def merge_component_findings(self, findings: list["Finding"]) -> None:
        """Merge binary-detected component findings into this SBOM, in place.

        Statically-linked third-party libraries (OpenSSL, BusyBox, …) appear in
        binaries' version strings but in no package-manager database, so the
        ``components`` check finds them where the package-DB walk cannot. This
        folds those findings into the SBOM so the BOM is the single complete
        inventory.

        Deduplication: a binary-sourced component is skipped if a component with
        the same ``(name, version)`` already exists from *any* source — the
        package database is the more authoritative record when both agree. Among
        binary-sourced components the first occurrence (by finding order, which
        the ``components`` check keeps stable) wins. Components are appended after
        the package-database components so existing ordering is preserved.
        """
        existing: set[tuple[str, str]] = {
            (c.name, c.version) for c in self.components
        }
        for finding in findings:
            comp = Component.from_component_finding(finding)
            if comp is None:
                continue
            key = (comp.name, comp.version)
            if key in existing:
                continue
            existing.add(key)
            self.components.append(comp)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _parse_stanzas(text: str) -> list[dict[str, str]]:
    """Parse a deb822/apk-style stanza file into a list of field maps.

    Stanzas are separated by one or more blank lines. Within a stanza each
    record is ``Key: value``; continuation lines (a line starting with a space
    or tab) are appended to the previous field's value. apk's single-letter
    keys (``P:foo``) use the same colon separator and parse identically.
    """
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None

    for raw in text.splitlines():
        if raw.strip() == "":
            if current:
                stanzas.append(current)
                current = {}
                last_key = None
            continue
        # Continuation line (deb822): leading whitespace appends to last field.
        if raw[0] in (" ", "\t") and last_key is not None:
            current[last_key] += "\n" + raw.strip()
            continue
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        if not key:
            continue
        current[key] = value.strip()
        last_key = key

    if current:
        stanzas.append(current)
    return stanzas


def _first_line(value: str | None) -> str | None:
    if not value:
        return None
    line = value.splitlines()[0].strip()
    return line or None


def _component_from_dpkg(stanza: dict[str, str], db_path: str) -> Component | None:
    """Map a dpkg /var/lib/dpkg/status stanza to a Component.

    Only packages whose Status indicates they are actually installed are
    emitted — dpkg keeps stanzas for removed/config-files packages too, and an
    inventory should reflect what is on the device, not its history.
    """
    name = stanza.get("Package")
    version = stanza.get("Version")
    if not name or not version:
        return None
    status = stanza.get("Status", "")
    # e.g. "install ok installed" — require the final word to be "installed".
    if status and status.split()[-1:] != ["installed"]:
        return None
    return Component(
        name=name,
        version=version,
        source="dpkg",
        architecture=stanza.get("Architecture"),
        description=_first_line(stanza.get("Description")),
        db_path=db_path,
    )


def _component_from_opkg(stanza: dict[str, str], db_path: str) -> Component | None:
    """Map an opkg status / .control stanza to a Component."""
    name = stanza.get("Package")
    version = stanza.get("Version")
    if not name or not version:
        return None
    status = stanza.get("Status", "")
    if status and status.split()[-1:] != ["installed"]:
        return None
    return Component(
        name=name,
        version=version,
        source="opkg",
        architecture=stanza.get("Architecture"),
        description=_first_line(stanza.get("Description")),
        db_path=db_path,
    )


def _component_from_apk(stanza: dict[str, str], db_path: str) -> Component | None:
    """Map an apk /lib/apk/db/installed stanza to a Component.

    apk uses single-letter keys:
        P=package  V=version  A=arch  T=description  L=license
    """
    name = stanza.get("P")
    version = stanza.get("V")
    if not name or not version:
        return None
    return Component(
        name=name,
        version=version,
        source="apk",
        architecture=stanza.get("A"),
        description=_first_line(stanza.get("T")),
        license_id=stanza.get("L"),
        db_path=db_path,
    )


def _dedupe(components: list[Component]) -> list[Component]:
    """Drop duplicate (source, name, version) components.

    opkg in particular lists each package in both a central ``status`` file and
    a per-package ``.control`` file; without dedup the same package appears
    twice. Order is preserved (first occurrence wins) so output is stable.
    """
    seen: set[tuple[str, str, str]] = set()
    out: list[Component] = []
    for c in components:
        key = (c.source, c.name, c.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# Relative path suffixes (POSIX) that identify each package database. unblob
# nests extracted filesystems in subdirectories, so the firmware root may sit
# many levels below the extract root — databases are matched by their path
# *suffix* anywhere in the tree rather than only at a fixed absolute location.
_DPKG_STATUS_SUFFIX = "var/lib/dpkg/status"
_OPKG_STATUS_SUFFIXES = (
    "var/lib/opkg/status",
    "usr/lib/opkg/status",
    "etc/opkg/status",
)
_OPKG_INFO_DIR_SUFFIX = "var/lib/opkg/info"
_APK_DB_SUFFIX = "lib/apk/db/installed"


def _posix(path: Path, root: Path) -> str:
    return _rel(path, root).replace("\\", "/")


def _collect_from_file(
    path: Path, root: Path, mapper, components: list[Component]
) -> None:
    text = _read_text(path)
    if text is None:
        return
    rel = _rel(path, root)
    for stanza in _parse_stanzas(text):
        comp = mapper(stanza, rel)
        if comp is not None:
            components.append(comp)


def scan(extract_root: str | Path) -> Sbom:
    """Scan the extracted tree under ``extract_root`` and build an Sbom.

    Walks the whole tree once and inspects every supported package database it
    finds, identified by its conventional path suffix (e.g. any
    ``…/var/lib/dpkg/status``). unblob nests extracted root filesystems in
    subdirectories, so databases are matched by suffix anywhere under the
    extract root rather than only at the top level. A missing database
    contributes nothing; a malformed stanza is skipped. Components are
    deduplicated and returned in a stable (discovery) order.
    """
    root = Path(extract_root)
    components: list[Component] = []

    if not root.exists():
        return Sbom(components=[])

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        rel_posix = _posix(path, root)

        if path.is_file():
            if rel_posix == _DPKG_STATUS_SUFFIX or rel_posix.endswith(
                "/" + _DPKG_STATUS_SUFFIX
            ):
                _collect_from_file(path, root, _component_from_dpkg, components)
            elif any(
                rel_posix == s or rel_posix.endswith("/" + s)
                for s in _OPKG_STATUS_SUFFIXES
            ):
                _collect_from_file(path, root, _component_from_opkg, components)
            elif rel_posix == _APK_DB_SUFFIX or rel_posix.endswith(
                "/" + _APK_DB_SUFFIX
            ):
                _collect_from_file(path, root, _component_from_apk, components)
        elif path.is_dir():
            if rel_posix == _OPKG_INFO_DIR_SUFFIX or rel_posix.endswith(
                "/" + _OPKG_INFO_DIR_SUFFIX
            ):
                for control in sorted(path.glob("*.control")):
                    if control.is_file() and not control.is_symlink():
                        _collect_from_file(
                            control, root, _component_from_opkg, components
                        )

    return Sbom(components=_dedupe(components))
