"""frisk command-line entry point."""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="frisk",
        description="Vet a third-party MCP server before you trust it.",
    )
    parser.add_subparsers(dest="command")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
