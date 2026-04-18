"""Standalone CLI for the EASM GitHub/npm engine.

Usage:
    python -m app.ingest.github_npm.cli example.com
    python -m app.ingest.github_npm.cli example.com --no-keyword-search
    python -m app.ingest.github_npm.cli example.com --threshold 0.5 -o out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from app.ingest.github_npm.engine import DEFAULT_CONFIDENCE_THRESHOLD, EASMEngine, Mode


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m app.ingest.github_npm.cli",
        description="EASM GitHub/npm attribution and discovery engine.",
    )
    p.add_argument("domain", help="Target domain, e.g. example.com")
    p.add_argument(
        "--mode", choices=[m.value for m in Mode], default=Mode.DISCOVERY.value,
        help="Engine mode (default: discovery)",
    )
    p.add_argument(
        "--threshold", type=float, default=DEFAULT_CONFIDENCE_THRESHOLD,
        help=f"Confidence threshold 0..1 (default: {DEFAULT_CONFIDENCE_THRESHOLD})",
    )
    p.add_argument("--no-keyword-search", action="store_true",
                   help="Skip GitHub code keyword search (fastest mode)")
    p.add_argument("--no-exposed-file-scan", action="store_true",
                   help="Skip path-based exposed-secret-file probes")
    p.add_argument("--no-pkg-enrichment", action="store_true",
                   help="Skip package.json reverse-attribution pass")
    p.add_argument("--max-users", type=int, default=200)
    p.add_argument("--max-packages", type=int, default=250)
    p.add_argument("--max-keyword-results", type=int, default=50)
    p.add_argument("--org-hint", action="append", default=[],
                   help="Candidate org login to check directly (repeatable)")
    p.add_argument("-o", "--output", help="Write JSON to file instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


async def _run(args: argparse.Namespace) -> int:
    engine = EASMEngine(
        confidence_threshold=args.threshold,
        enable_keyword_search=not args.no_keyword_search,
        enable_exposed_file_scan=not args.no_exposed_file_scan,
        enable_package_json_enrichment=not args.no_pkg_enrichment,
        max_users=args.max_users,
        max_packages=args.max_packages,
        max_keyword_results=args.max_keyword_results,
        org_login_hints=args.org_hint,
    )
    result = await engine.run(args.domain, mode=Mode(args.mode))
    payload = json.dumps(result.to_dict(), indent=2, default=str)
    if args.output:
        with open(args.output, "w") as f:
            f.write(payload)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(payload)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if not os.environ.get("GITHUB_TOKEN") and not os.environ.get("GITHUB_TOKENS"):
        print(
            "INFO: no GITHUB_TOKEN set — running fully unauthenticated. "
            "GitHub code search will be skipped (endpoint requires auth). "
            "Other discovery runs at the 60 req/hr unauth cap. Set GITHUB_TOKEN "
            "(any throwaway PAT — not credentials against the target) to raise "
            "the cap to 5000 req/hr and enable code search.",
            file=sys.stderr,
        )
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
