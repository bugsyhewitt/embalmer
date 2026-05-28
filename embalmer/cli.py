"""embalmer command-line interface.

Article II (CLI Interface Mandate): the pipeline is fully driven from the CLI,
text/file in, JSON or markdown out.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .binaries import AutopsyError, BlightError
from .diff import BaselineError, compute_diff, load_baseline
from .diff import render as render_diff
from .extract import ExtractionError
from .pipeline import run
from .report import render

DEFAULT_WORKDIR = "./embalmer-work/"


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
        required=True,
        help="path to the firmware image (raw blob, ZIP, tarball, etc.)",
    )
    parser.add_argument(
        "--workdir",
        default=DEFAULT_WORKDIR,
        help=f"extraction directory (default: {DEFAULT_WORKDIR})",
    )
    parser.add_argument(
        "--checks",
        choices=["extract", "creds", "certs", "binaries", "sbom", "all"],
        default="all",
        help="which checks to run (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "md"],
        default="json",
        dest="fmt",
        help="report output format (default: json)",
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
        "--version",
        action="version",
        version=f"embalmer {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    baseline_data = None
    if args.baseline:
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
            firmware=args.firmware,
            workdir=args.workdir,
            checks=args.checks,
            analyzer=args.analyzer,
            blight_binary=args.blight_binary,
            autopsy_binary=args.autopsy_binary,
            extractor=args.extractor,
            enrich=not args.no_enrich,
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
