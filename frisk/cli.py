"""frisk command-line entry point: `frisk scan` and `frisk verify`."""

from __future__ import annotations

import argparse
import os
import sys

from frisk.connector import ConnectorError, RemoteTarget, StdioTarget, Target, enumerate_target
from frisk.core.detectors import ALL_DETECTORS
from frisk.core.engine import run_detectors
from frisk.core.models import Finding, Inventory, Severity
from frisk.core.report import render_human, render_json
from frisk.core.sanitize import c0_escape
from frisk.core.score import Assessment, assess, exit_code
from frisk.lockfile import LockError, diff_lock, read_lock, render_diff, write_lock
from frisk.sandbox import SandboxOptions, inspect_decoys, prepare_stdio, scan_for_canary

DEFAULT_LOCK = "frisk.lock"
DEFAULT_AUTH_ENV = "FRISK_AUTH_TOKEN"
EXIT_OPERATIONAL_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="frisk",
        description="Vet a third-party MCP server before you trust it.",
    )
    sub = parser.add_subparsers(dest="command")

    for name, help_text in (
        ("scan", "connect, enumerate, and risk-score an MCP server"),
        ("verify", "re-enumerate and diff against a frisk.lock baseline (rug-pull check)"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("target", help="stdio command, or an http(s):// URL for a remote server")
        p.add_argument(
            "args",
            nargs=argparse.REMAINDER,
            help="arguments passed to the stdio command (after the command name)",
        )
        p.add_argument("--no-sandbox", action="store_true", help="disable the seatbelt sandbox")
        p.add_argument(
            "--transport",
            choices=["auto", "http", "sse"],
            default="auto",
            help="remote transport (default: auto)",
        )
        p.add_argument(
            "--auth-env",
            default=DEFAULT_AUTH_ENV,
            help=f"env var holding a remote bearer token (default: {DEFAULT_AUTH_ENV})",
        )
        p.add_argument("--timeout", type=float, default=30.0, help="hard wall-clock timeout (s)")
        p.add_argument(
            "--lock", default=DEFAULT_LOCK, help=f"lockfile path (default: {DEFAULT_LOCK})"
        )

    scan = sub.choices["scan"]
    scan.add_argument("--format", choices=["human", "json"], default="human")
    scan.add_argument("--no-lock", action="store_true", help="do not write a frisk.lock")

    return parser


def _build_target(args: argparse.Namespace) -> Target:
    target = args.target
    if target.startswith(("http://", "https://")):
        token = os.environ.get(args.auth_env) if args.auth_env else None
        return RemoteTarget(url=target, auth_token=token, transport=args.transport)
    # stdio: env is intentionally empty — the sandbox layers a benign allowlist on top and
    # forces a fake HOME, so the untrusted server never inherits frisk's own secrets (S3).
    stdio_args = [a for a in args.args if a != "--"]
    return StdioTarget(command=target, args=stdio_args, env={}, cwd=os.getcwd())


def _enumerate(args: argparse.Namespace) -> tuple[Inventory, list[Finding]]:
    """Sandbox (for stdio) then enumerate; returns the Inventory plus honeypot findings
    (R24). Raises ConnectorError on any failure (R6). Remote targets have no sandbox and
    therefore no honeypot — their findings list is always empty."""
    target = _build_target(args)
    if isinstance(target, StdioTarget):
        options = SandboxOptions(enabled=not args.no_sandbox, timeout_seconds=args.timeout)
        sandboxed = prepare_stdio(target, options)
        if sandboxed.warning:
            print(f"warning: {sandboxed.warning}", file=sys.stderr)
        if sandboxed.decoys is not None and not sandboxed.decoys.atime_reliable:
            # Degraded, not disabled: tamper + canary-exfiltration detection still work.
            print(
                "warning: filesystem does not update atime on read — honeypot decoy-read "
                "detection is degraded (tamper and exfiltration detection still active)",
                file=sys.stderr,
            )
        try:
            inventory = enumerate_target(sandboxed.target, timeout=sandboxed.timeout_seconds)
            # Inspect decoys BEFORE the fake HOME is cleaned up, and only after the child
            # has exited (enumerate_target returns with the transport closed).
            honeypot_findings = inspect_decoys(sandboxed.decoys) + scan_for_canary(
                inventory, sandboxed.decoys
            )
            return inventory, honeypot_findings
        finally:
            _cleanup(sandboxed)
    return enumerate_target(target, timeout=args.timeout), []


def _cleanup(sandboxed) -> None:
    import shutil

    for path in sandboxed._cleanup:
        shutil.rmtree(path, ignore_errors=True)


def _cmd_scan(args: argparse.Namespace) -> int:
    inventory, honeypot_findings = _enumerate(args)
    findings = run_detectors(inventory, ALL_DETECTORS) + honeypot_findings
    assessment: Assessment = assess(findings)
    if args.format == "json":
        sys.stdout.write(render_json(inventory, findings, assessment))
    else:
        sys.stdout.write(render_human(inventory, findings, assessment))
    if not args.no_lock:
        try:
            write_lock(args.lock, inventory)
            if args.format != "json":
                print(f"\nwrote baseline: {args.lock}", file=sys.stderr)
        except OSError as exc:
            # The verdict is the primary output; a failed baseline write is a warning, not a
            # crash — and must not mask the risk exit code.
            print(f"warning: could not write lockfile {args.lock}: {type(exc).__name__}",
                  file=sys.stderr)
    return exit_code(assessment)


def _honeypot_line(f: Finding) -> str:
    """One stderr line per honeypot finding. item_ref can embed a server-controlled tool
    name (canary-in-raw-bytes branch), so everything is C0-escaped before hitting the
    terminal (R15) — this is the only Finding sink outside the core renderers."""
    return f"honeypot: [{f.severity.name}] {c0_escape(f.item_ref)} — {c0_escape(f.message)}"


def _cmd_verify(args: argparse.Namespace) -> int:
    locked = read_lock(args.lock)
    inventory, honeypot_findings = _enumerate(args)
    diff = diff_lock(locked, inventory)
    sys.stdout.write(render_diff(diff))
    # A verify run that catches the server stealing decoy credentials must not exit 0,
    # even when the definitions themselves have not drifted (R24, R18). INFO-level
    # honeypot notes (e.g. an inspection error) are reported but do not gate.
    for f in honeypot_findings:
        print(_honeypot_line(f), file=sys.stderr)
    if any(f.severity >= Severity.HIGH for f in honeypot_findings):
        return EXIT_OPERATIONAL_ERROR
    return EXIT_OPERATIONAL_ERROR if diff.changed else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        return _cmd_verify(args)
    except ConnectorError as exc:
        # Fail loud, never "clean": a specific, actionable error and a non-zero exit (R6).
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except LockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    sys.exit(main())
