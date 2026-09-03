"""Command-line interface for ownscan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ownscan import __version__
from ownscan.report import render_json, render_text
from ownscan.scan import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ownscan",
        description=(
            "Scan a local file or directory for leaked secrets and common "
            "misconfigurations. Ownscan never opens a network connection."
        ),
    )
    parser.add_argument("path", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON instead of text",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ownscan {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target: Path = args.path
    if not target.exists():
        print(f"ownscan: path not found: {target}", file=sys.stderr)
        return 2

    findings = scan_path(target)
    if args.json:
        print(render_json(findings))
    else:
        text = render_text(findings)
        if text:
            print(text)
        else:
            print("No findings.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
