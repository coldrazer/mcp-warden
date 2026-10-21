"""CLI: mcpwarden scan TARGET [--format text|json|html] [--probe] [-o OUTPUT]"""

import argparse
import sys
from pathlib import Path

from . import __version__, probe
from .engine import scan_target
from .report import build_payload, render_html, render_json, render_text
from .score import score_result


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mcpwarden",
        description="MCP Warden: security scanner for MCP servers",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a Python file or directory")
    scan.add_argument("target", help="Python file or directory to scan")
    scan.add_argument(
        "--format", choices=["text", "json", "html"], default="text",
        help="Report format (default: text)",
    )
    scan.add_argument(
        "--probe", action="store_true",
        help="Dynamically probe the target locally to confirm path traversal",
    )
    scan.add_argument("-o", "--output", help="Write the report to a file instead of stdout")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        result = scan_target(args.target)
        scored = score_result(result)
        if args.probe:
            result.probe = probe.probe_target(args.target)
        payload = build_payload(result, scored)
        if args.format == "json":
            output = render_json(payload)
        elif args.format == "html":
            output = render_html(payload)
        else:
            output = render_text(payload)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 1 if result.findings else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
