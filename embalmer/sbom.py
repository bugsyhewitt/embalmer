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
from typing import Any
from urllib.parse import quote

# CycloneDX spec version emitted. 1.6 is the current ECMA-424 release and adds
# the IoT/hardware BOM and native VEX support called out in POST_V01.md.
CYCLONEDX_SPEC_VERSION = "1.6"

# Don't try to read multi-megabyte blobs as package databases.
_MAX_READ_BYTES = 50_000_000


@dataclass
class Component:
    """A single installed package, normalized across package managers."""

    name: str
    version: str
    # One of: "dpkg", "opkg", "apk" — the database the component came from.
    source: str
    architecture: str | None = None
    description: str | None = None
    license_id: str | None = None
    # Relative path (under the extract root) of the database file this came from.
    db_path: str = ""

    def purl(self) -> str:
        """A Package URL (purl) identifying this component.

        purls are the CycloneDX-recommended component identifier and the key
        downstream tools use to match against vulnerability databases. The
        ``type`` namespace maps the package manager:

            dpkg -> pkg:deb     opkg -> pkg:opkg     apk -> pkg:apk
        """
        purl_type = {"dpkg": "deb", "opkg": "opkg", "apk": "apk"}.get(
            self.source, self.source
        )
        base = f"pkg:{purl_type}/{quote(self.name, safe='')}@{quote(self.version, safe='')}"
        if self.architecture:
            base += f"?arch={quote(self.architecture, safe='')}"
        return base

    def to_cyclonedx(self) -> dict[str, Any]:
        """Render this component as a CycloneDX 1.6 component object."""
        comp: dict[str, Any] = {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl(),
            "properties": [
                {"name": "embalmer:package-manager", "value": self.source},
                {"name": "embalmer:database", "value": self.db_path},
            ],
        }
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
                }
                for c in self.components
            ],
        }


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
