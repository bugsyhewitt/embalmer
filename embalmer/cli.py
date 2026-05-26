"""embalmer command-line interface.

Article II (CLI Interface Mandate): the pipeline is fully driven from the CLI,
text/file in, JSON or markdown out.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .binaries import BlightError
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
        choices=["extract", "creds", "binaries", "all"],
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
        "--blight-binary",
        default="blight",
        help="path to the blight executable for the binary-analysis handoff "
        "(default: 'blight' on PATH)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="write the report to this file instead of stdout",
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

    try:
        report = run(
            firmware=args.firmware,
            workdir=args.workdir,
            checks=args.checks,
            blight_binary=args.blight_binary,
        )
    except ExtractionError as exc:
        print(f"embalmer: extraction failed: {exc}", file=sys.stderr)
        return 2
    except BlightError as exc:
        print(f"embalmer: binary analysis failed: {exc}", file=sys.stderr)
        return 3

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
