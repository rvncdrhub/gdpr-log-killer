"""
CLI entry point: gdpr-log-killer

Usage examples:
  gdpr-log-killer app.log
  gdpr-log-killer -d corp.example.com -d internal app.log > clean.log
  cat app.log | gdpr-log-killer --stdin
"""

from __future__ import annotations

import argparse
import json
import sys

from .sanitizer import Sanitizer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gdpr-log-killer",
        description="Strip GDPR-sensitive values from log files.",
    )
    p.add_argument(
        "file",
        nargs="?",
        metavar="FILE",
        help="Log file to sanitize (omit to read from stdin).",
    )
    p.add_argument(
        "--stdin",
        action="store_true",
        help="Read from stdin (implied when FILE is omitted).",
    )
    p.add_argument(
        "-d",
        "--domain",
        action="append",
        metavar="DOMAIN",
        dest="domains",
        default=[],
        help="Internal domain suffix to strip (repeatable). E.g. corp.acme.com",
    )
    p.add_argument(
        "--no-ips",
        action="store_false",
        dest="strip_ips",
        default=True,
    )
    p.add_argument("--no-emails", action="store_false", dest="strip_emails", default=True)
    p.add_argument("--no-macs", action="store_false", dest="strip_macs", default=True)
    p.add_argument("--no-users", action="store_false", dest="strip_users", default=True)
    p.add_argument("--no-phones", action="store_false", dest="strip_phones", default=True)
    p.add_argument(
        "--strip-uuids",
        action="store_true",
        dest="strip_uuids",
        default=False,
        help="Also replace UUIDs / session tokens (off by default).",
    )
    p.add_argument(
        "--report",
        action="store_true",
        help="Print a JSON summary of what was replaced to stderr.",
    )
    p.add_argument(
        "--show-mapping",
        action="store_true",
        help="Include the placeholder→original mapping in the --report output.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.file:
        try:
            text = open(args.file, encoding="utf-8", errors="replace").read()
        except OSError as exc:
            print(f"gdpr-log-killer: {exc}", file=sys.stderr)
            return 1
    else:
        text = sys.stdin.read()

    sanitizer = Sanitizer(
        strip_ips=args.strip_ips,
        strip_emails=args.strip_emails,
        strip_macs=args.strip_macs,
        strip_hostnames=bool(args.domains),
        strip_users=args.strip_users,
        strip_uuids=args.strip_uuids,
        strip_phones=args.strip_phones,
        internal_domains=args.domains,
    )

    result = sanitizer.sanitize(text)
    sys.stdout.write(result.text)

    if args.report:
        report: dict = {"stats": result.stats}
        if args.show_mapping:
            report["mapping"] = result.mapping
        print(json.dumps(report, indent=2), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
