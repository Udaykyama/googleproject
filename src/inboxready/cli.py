"""Command-line interface for InboxReady."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .audit import audit
from .dnsresolver import DnsError, Resolver, StaticResolver, SystemResolver, is_valid_hostname
from .domains import PublicSuffixList
from .models import Severity
from .report import FORMATS, render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_EPILOG = """\
examples:
  inboxready example.com
  inboxready example.com --selector google --ip 203.0.113.10
  inboxready example.com --message campaign.eml --spam-rate 0.08 --daily-volume 120000
  inboxready --message campaign.eml --offline
  inboxready example.com --fixture examples/fixtures/failing-sender.json --format markdown
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inboxready",
        description=(
            "Audit a sending domain and message against Google's Gmail bulk sender "
            "requirements (SPF, DKIM, DMARC, FCrDNS, TLS, RFC 8058 one-click unsubscribe)."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="the sending domain to audit, e.g. mail.example.com",
    )
    parser.add_argument("--version", action="version", version=f"inboxready {__version__}")

    source = parser.add_argument_group("input")
    source.add_argument(
        "-m",
        "--message",
        metavar="FILE",
        help="raw .eml message to audit (use '-' to read from stdin)",
    )
    source.add_argument(
        "--selector",
        action="append",
        default=[],
        metavar="NAME",
        dest="selectors",
        help="DKIM selector to check; repeatable. Without it, common selectors are probed.",
    )
    source.add_argument(
        "--ip",
        action="append",
        default=[],
        metavar="ADDR",
        dest="ips",
        help="sending IP to check for forward-confirmed reverse DNS; repeatable",
    )
    source.add_argument(
        "--daily-volume",
        type=int,
        metavar="N",
        help="messages sent to Gmail in 24h, used to classify bulk-sender status",
    )
    source.add_argument(
        "--spam-rate",
        type=float,
        metavar="PCT",
        help="spam complaint rate from Postmaster Tools as a percentage, e.g. 0.08",
    )
    source.add_argument(
        "--transactional",
        action="store_true",
        help="treat the message as transactional, not bulk (skips unsubscribe requirements)",
    )

    resolution = parser.add_argument_group("resolution")
    resolution.add_argument(
        "--fixture",
        metavar="FILE",
        help="answer DNS from a JSON fixture instead of the network (fully offline)",
    )
    resolution.add_argument(
        "--offline",
        action="store_true",
        help="skip all DNS checks; audit the message only",
    )
    resolution.add_argument(
        "--nameserver",
        metavar="ADDR",
        help="query this resolver instead of the system default",
    )
    resolution.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="per-query DNS timeout (default: 5)",
    )
    resolution.add_argument(
        "--public-suffix-list",
        metavar="FILE",
        help="path to Mozilla's public_suffix_list.dat for exact organizational domains",
    )
    resolution.add_argument(
        "--no-probe-selectors",
        action="store_true",
        help="do not guess DKIM selectors when none are given",
    )
    resolution.add_argument(
        "--no-expand-spf",
        action="store_true",
        help="do not follow include:/redirect= chains when counting SPF lookups",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default="text",
        help="output format (default: text)",
    )
    output.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to a file instead of stdout",
    )
    output.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity if s is not Severity.PASS],
        default="critical",
        help="exit non-zero when a finding at this severity or worse is present "
        "(default: critical)",
    )
    colour = output.add_mutually_exclusive_group()
    colour.add_argument("--color", action="store_true", help="force ANSI colour output")
    colour.add_argument("--no-color", action="store_true", help="disable ANSI colour output")
    return parser


def _read_message(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _build_resolver(args: argparse.Namespace) -> Resolver | None:
    if args.offline:
        return None
    if args.fixture:
        return StaticResolver.from_file(args.fixture)
    return SystemResolver(timeout=args.timeout, nameserver=args.nameserver)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.domain and not args.message:
        parser.error("give a domain to audit, a --message to inspect, or both")
    if args.domain and not is_valid_hostname(args.domain):
        parser.error(f"{args.domain!r} is not a valid domain name")
    if args.offline and args.fixture:
        parser.error("--offline and --fixture are mutually exclusive")
    if args.offline and not args.message:
        parser.error("--offline audits a message; pass --message")

    try:
        raw_message = _read_message(args.message) if args.message else None
    except OSError as exc:
        print(f"inboxready: cannot read message: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        psl = (
            PublicSuffixList.from_file(args.public_suffix_list)
            if args.public_suffix_list
            else PublicSuffixList()
        )
    except (OSError, ValueError) as exc:
        print(f"inboxready: cannot load public suffix list: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        resolver = _build_resolver(args)
    except (OSError, ValueError, DnsError) as exc:
        print(f"inboxready: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        report = audit(
            resolver=resolver,
            domain=args.domain,
            raw_message=raw_message,
            selectors=args.selectors,
            ips=args.ips,
            daily_volume=args.daily_volume,
            spam_rate=args.spam_rate,
            bulk=False if args.transactional else None,
            psl=psl,
            probe_selectors=not args.no_probe_selectors,
            expand_spf=not args.no_expand_spf,
        )
    except DnsError as exc:
        print(f"inboxready: DNS error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"inboxready: {exc}", file=sys.stderr)
        return EXIT_USAGE

    color = True if args.color else (False if args.no_color else None)
    rendered = render(report, fmt=args.format, color=color)

    if args.output:
        try:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"inboxready: cannot write report: {exc}", file=sys.stderr)
            return EXIT_USAGE
    else:
        print(rendered)

    threshold = Severity.from_label(args.fail_on)
    return EXIT_FINDINGS if report.worst.rank >= threshold.rank else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
