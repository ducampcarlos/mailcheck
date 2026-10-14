"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .models import Report, Severity
from .resolver import DnsResolver
from .runner import run_checks

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2

_COLOURS = {
    Severity.INFO: "\033[36m",
    Severity.LOW: "\033[33m",
    Severity.MEDIUM: "\033[38;5;208m",
    Severity.HIGH: "\033[31m",
}
_OK, _RESET, _DIM = "\033[32m", "\033[0m", "\033[2m"


def render_text(report: Report, colour: bool) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    lines = [
        f"mailcheck report for {report.domain}",
        f"score {report.score}/100  grade {report.grade}",
        "",
    ]
    for finding in report.findings:
        if finding.ok:
            tag = paint(_OK, " ok   ")
        else:
            tag = paint(_COLOURS[finding.severity], f"{finding.severity.label:<6}")
        lines.append(f"[{tag}] {finding.check}: {finding.message}")
        if finding.remediation and not finding.ok:
            lines.append(paint(_DIM, f"         fix: {finding.remediation}"))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailcheck",
        description="Passive email-authentication health check (SPF, DKIM, DMARC, MX, MTA-STS).",
    )
    parser.add_argument("domain", help="domain to check, e.g. example.com")
    parser.add_argument("-f", "--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--dkim-selector", action="append", default=[], metavar="NAME",
        help="extra DKIM selector to probe (repeatable)",
    )  # fmt: skip
    parser.add_argument(
        "--fail-on", choices=("none", "low", "medium", "high"), default="high",
        help="exit 1 when a finding of this severity or worse exists (default: high)",
    )  # fmt: skip
    parser.add_argument(
        "--nameserver", metavar="IP", help="query this DNS server instead of the system one"
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout in seconds")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    resolver = DnsResolver(timeout=args.timeout, nameserver=args.nameserver)
    report = run_checks(resolver, args.domain, tuple(args.dkim_selector))

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report, colour=sys.stdout.isatty() and not args.no_color))

    if args.fail_on == "none":
        return EXIT_OK
    threshold = Severity[args.fail_on.upper()]
    worst = report.worst()
    return EXIT_FINDINGS if worst is not None and worst >= threshold else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
