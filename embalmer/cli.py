"""embalmer command-line interface.

Article II (CLI Interface Mandate): the pipeline is fully driven from the CLI,
text/file in, JSON or markdown out.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .binaries import AutopsyError, BlightError
from .diff import BaselineError, compute_diff, load_baseline
from .diff import render as render_diff
from .extract import ExtractionError
from .fetch import FetchError, fetch
from .pipeline import run
from .report import render

DEFAULT_WORKDIR = "./embalmer-work/"
DEFAULT_FETCH_NAME = "firmware.bin"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="embalmer",
        description=(
            "Firmware analysis pipeline — orchestrates unblob extraction, "
            "credential scanning, and binary analysis (handoff to blight) "
            "into a single structured firmware audit report."
        ),
        epilog=(
            "Ethical use only: analyze firmware you own or are explicitly "
            "authorized to assess."
        ),
    )
    parser.add_argument(
        "--firmware",
        default=None,
        help="path to the firmware image (raw blob, ZIP, tarball, etc.). "
        "Required unless --fetch-url is given, in which case it is the local "
        "path the downloaded image is written to (default: a file under "
        "--workdir)",
    )
    parser.add_argument(
        "--fetch-url",
        default=None,
        metavar="URL",
        dest="fetch_url",
        help="download the firmware image from this vendor URL via graverobber "
        "before analyzing it, instead of supplying a local --firmware blob. "
        "graverobber handles vendor-specific download formats and "
        "authentication; embalmer then runs the normal extract->analyze "
        "pipeline on the downloaded image ('point at a vendor URL, get an "
        "audit report')",
    )
    parser.add_argument(
        "--graverobber-binary",
        default="graverobber",
        dest="graverobber_binary",
        help="path to the graverobber executable used by --fetch-url "
        "(default: 'graverobber' on PATH)",
    )
    parser.add_argument(
        "--workdir",
        default=DEFAULT_WORKDIR,
        help=f"extraction directory (default: {DEFAULT_WORKDIR})",
    )
    parser.add_argument(
        "--checks",
        choices=["extract", "creds", "certs", "binaries", "sbom", "components", "all"],
        default="all",
        help="which checks to run (default: all). 'components' detects "
        "third-party component versions (BusyBox, OpenSSL, curl, …) from "
        "version strings baked into the firmware",
    )
    parser.add_argument(
        "--format",
        choices=["json", "md", "csv", "sarif"],
        default="json",
        dest="fmt",
        help="report output format (default: json). 'csv' emits a flat, "
        "one-row-per-finding table of every credential, certificate, binary, "
        "and component finding — import it straight into a spreadsheet or "
        "triage tool. 'sarif' emits a SARIF 2.1.0 document of the same finding "
        "inventory — the format GitHub Code Scanning and most SAST dashboards "
        "ingest directly. The SBOM and extraction tree are only in 'json'. "
        "'csv' and 'sarif' are not supported with --baseline (the diff is not "
        "a finding list)",
    )
    parser.add_argument(
        "--extractor",
        choices=["unblob", "binwalk", "auto"],
        default="auto",
        help="extraction backend: 'unblob' (primary, broadest format support), "
        "'binwalk' (binwalk v3 heuristic signature scanning), or 'auto' (the "
        "default — try unblob first and fall back to binwalk if unblob fails "
        "or produces no files)",
    )
    parser.add_argument(
        "--sbom-format",
        choices=["cyclonedx", "spdx", "both"],
        default="cyclonedx",
        dest="sbom_format",
        help="which SBOM document format(s) to emit for the 'sbom' check: "
        "'cyclonedx' (CycloneDX 1.6, the default, under the report's `sbom.bom` "
        "key), 'spdx' (SPDX 2.3, under `sbom.spdx`), or 'both'. CycloneDX and "
        "SPDX are the two NTIA-recognized SBOM formats; some consumers ingest "
        "only one",
    )
    parser.add_argument(
        "--sbom-ntia-check",
        action="store_true",
        default=False,
        dest="ntia_check",
        help="score the SBOM against the NTIA SBOM minimum-elements (July 2021, "
        "the EO-14028 baseline) and attach a pass/fail conformance report under "
        "the report's `sbom.ntia` key. Checks the seven minimum elements "
        "(Supplier Name, Component Name, Version, Other Unique Identifiers, "
        "Dependency Relationship, Author of SBOM Data, Timestamp). Requires the "
        "'sbom' check; embalmer-generated BOMs satisfy every element except "
        "Supplier Name, which it cannot resolve from firmware (reported as the "
        "honest gap rather than overclaimed)",
    )
    parser.add_argument(
        "--sbom-validate-spdx",
        action="store_true",
        default=False,
        dest="spdx_validate_check",
        help="validate the structural integrity of the generated SPDX 2.3 "
        "relationship graph and attach a pass/fail report under the report's "
        "`sbom.spdx_validation` key. The structural companion to "
        "--sbom-ntia-check: NTIA checks the document's content (minimum data "
        "fields), this checks its graph (unique/well-formed SPDXIDs, no dangling "
        "relationship endpoints, a DESCRIBES root, no orphaned packages) — the "
        "invariants strict SPDX validators (the SPDX online validator, ORT, "
        "ntia-conformance-checker) enforce. Requires the 'sbom' check",
    )
    parser.add_argument(
        "--sbom-validate-purl",
        action="store_true",
        default=False,
        dest="purl_validate_check",
        help="validate every CycloneDX component's purl (Package URL) against "
        "the package-url specification and attach a pass/fail report under the "
        "report's `sbom.purl_validation` key. The CycloneDX-side companion to "
        "--sbom-validate-spdx: the purl is the identifier downstream vuln "
        "scanners (Dependency-Track, Grype, OSV-Scanner) join on, and a "
        "malformed purl makes a component silently un-matchable. Checks the "
        "'pkg:' scheme, a valid lowercase type embalmer emits (deb/opkg/apk/"
        "generic), a present name and version, correctly percent-encoded "
        "segments, and well-formed qualifiers. Requires the 'sbom' check",
    )
    parser.add_argument(
        "--sbom-cve",
        action="store_true",
        default=False,
        dest="sbom_cve_check",
        help="cross-reference the SBOM's CPE-bearing components against the NVD "
        "(services.nvd.nist.gov) and attach the matched CVEs under the report's "
        "`sbom.vulnerabilities` key as a CycloneDX vulnerabilities[] array (with "
        "a CVSS rating and a CISA-KEV flag per CVE). This is the SBOM's "
        "vulnerability-list half: it surfaces the CVEs that touch the firmware's "
        "third-party libraries (e.g. OpenSSL 1.0.1f -> CVE-2014-0160) directly in "
        "the BOM. Self-contained — no ossuary dependency, reusing the same cached "
        "NVD client severity scoring uses. Only binary-detected components carry a "
        "CPE, so package-database components are not cross-referenced (NVD matches "
        "on CPE, not purl). Requires the 'sbom' check (and the 'components' check "
        "to populate CPE-bearing components); makes network calls and is skipped "
        "with --no-enrich (air-gapped)",
    )
    parser.add_argument(
        "--sbom-osv",
        action="store_true",
        default=False,
        dest="sbom_osv_check",
        help="cross-reference the SBOM's package-database components "
        "(dpkg/opkg/apk) against OSV.dev (api.osv.dev) and merge the matched "
        "CVEs into the report's `sbom.vulnerabilities` key. The companion to "
        "--sbom-cve: that flag handles only the CPE-bearing (binary-detected) "
        "components because NVD matches on CPE, not purl; --sbom-osv handles "
        "the package-database components NVD cannot name, using OSV.dev's "
        "purl-keyed index (the same upstream Dependabot and OSV-Scanner use). "
        "Pass both for a complete cross-reference of every SBOM component. "
        "Self-contained — no ossuary dependency, reusing the same cache and "
        "KEV/EPSS scoring as --sbom-cve. Requires the 'sbom' check; makes "
        "network calls and is skipped with --no-enrich (air-gapped)",
    )
    parser.add_argument(
        "--vex",
        action="store_true",
        default=False,
        dest="emit_vex",
        help="also emit a CycloneDX VEX (Vulnerability Exploitability eXchange) "
        "document under the report's `vex` key. VEX is the exploitability "
        "companion to the SBOM: it distills the binary findings' CVE evidence "
        "(CVSS + EPSS + CISA KEV) into a per-CVE assertion of whether the "
        "vulnerability is 'exploitable' (confirmed in KEV or high EPSS) or still "
        "'in_triage'. Requires the 'binaries' check and severity enrichment; "
        "with --no-enrich the VEX is empty",
    )
    parser.add_argument(
        "--analyzer",
        choices=["blight", "autopsy", "both"],
        default="blight",
        help="which binary analyzer to run for the 'binaries' check: 'blight' "
        "(fast pattern matcher, the default), 'autopsy' (angr symbolic "
        "execution, deeper CWE analysis), or 'both' (run both and aggregate)",
    )
    parser.add_argument(
        "--blight-binary",
        default="blight",
        help="path to the blight executable for the binary-analysis handoff "
        "(default: 'blight' on PATH)",
    )
    parser.add_argument(
        "--autopsy-binary",
        default="autopsy",
        help="path to the autopsy executable, used when --analyzer is 'autopsy' "
        "or 'both' (default: 'autopsy' on PATH)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="SCAN.json",
        help="compare this run against a previous embalmer JSON report and emit "
        "the delta (added/removed/severity-changed findings, SBOM component "
        "changes) instead of the full report — use to validate firmware "
        "upgrades ('did the vendor fix the CVE they claimed to?')",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=None,
        metavar="N",
        help="number of binaries to analyze in parallel during the 'binaries' "
        "check (default: half the CPU count). Use 1 to force sequential "
        "analysis. Large firmware images with hundreds of ELF binaries analyze "
        "far faster with parallelism since each blight/autopsy invocation is "
        "independent",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="write the report to this file instead of stdout",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        default=False,
        help="emit per-binary analysis progress to stderr (auto-enabled when "
        "--output writes the report to a file)",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        default=False,
        dest="no_enrich",
        help="skip CVSS/EPSS/KEV severity enrichment (for offline/air-gapped use)",
    )
    parser.add_argument(
        "--epss-threshold",
        type=float,
        default=None,
        metavar="P",
        dest="epss_threshold",
        help="EPSS probability (0.0-1.0) at or above which a finding's "
        "CVSS-based severity is promoted one triage tier — applies to both "
        "binary findings and --sbom-cve cross-reference matches (default: 0.5, "
        "'more likely than not to be exploited'). Lower is more aggressive "
        "(promotes more findings); a value above 1.0 disables EPSS promotion. "
        "Has no effect with --no-enrich",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"embalmer {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Resolve the firmware path: either downloaded via graverobber (--fetch-url)
    # or supplied directly (--firmware). Exactly one source must be available.
    firmware_path = args.firmware
    if args.fetch_url:
        # When fetching, --firmware (if given) is the download destination;
        # otherwise default to a file under the workdir.
        destination = args.firmware or os.path.join(args.workdir, DEFAULT_FETCH_NAME)
        try:
            firmware_path = str(
                fetch(
                    args.fetch_url,
                    destination,
                    graverobber_binary=args.graverobber_binary,
                )
            )
        except FetchError as exc:
            print(f"embalmer: firmware fetch failed: {exc}", file=sys.stderr)
            return 5
    elif not args.firmware:
        print(
            "embalmer: one of --firmware or --fetch-url is required",
            file=sys.stderr,
        )
        return 1

    if args.epss_threshold is not None and args.epss_threshold < 0:
        print(
            "embalmer: --epss-threshold must be >= 0 (EPSS is a 0.0-1.0 "
            "probability; pass a value above 1.0 to disable EPSS promotion)",
            file=sys.stderr,
        )
        return 1

    baseline_data = None
    if args.baseline:
        if args.fmt in ("csv", "sarif"):
            # The diff is a structured delta (added/removed/changed findings,
            # SBOM component changes), not a flat finding list, so it has no
            # natural CSV/SARIF shape. Fail fast with a clear message rather
            # than silently producing something misleading.
            print(
                f"embalmer: --format {args.fmt} is not supported with "
                "--baseline; use json or md for the diff report",
                file=sys.stderr,
            )
            return 1
        try:
            baseline_data = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"embalmer: {exc}", file=sys.stderr)
            return 4

    # Progress goes to stderr; auto-enable it when the report itself is being
    # written to a file (so stdout is not the human's window) unless the user
    # explicitly asked for it.
    show_progress = args.progress or bool(args.output)

    try:
        report = run(
            firmware=firmware_path,
            workdir=args.workdir,
            checks=args.checks,
            analyzer=args.analyzer,
            blight_binary=args.blight_binary,
            autopsy_binary=args.autopsy_binary,
            extractor=args.extractor,
            enrich=not args.no_enrich,
            epss_threshold=args.epss_threshold,
            sbom_format=args.sbom_format,
            ntia_check=args.ntia_check,
            spdx_validate_check=args.spdx_validate_check,
            purl_validate_check=args.purl_validate_check,
            sbom_cve_check=args.sbom_cve_check,
            sbom_osv_check=args.sbom_osv_check,
            emit_vex=args.emit_vex,
            jobs=args.jobs,
            progress=show_progress,
        )
    except ExtractionError as exc:
        print(f"embalmer: extraction failed: {exc}", file=sys.stderr)
        return 2
    except (BlightError, AutopsyError) as exc:
        print(f"embalmer: binary analysis failed: {exc}", file=sys.stderr)
        return 3

    if baseline_data is not None:
        diff = compute_diff(baseline_data, report)
        rendered = render_diff(diff, args.fmt)
    else:
        rendered = render(report, args.fmt)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
            if not rendered.endswith("\n"):
                fh.write("\n")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
