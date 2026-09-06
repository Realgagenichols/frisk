"""frisk command-line entry point: `frisk scan` and `frisk verify`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from frisk import __version__
from frisk.connector import ConnectorError, RemoteTarget, StdioTarget, Target, enumerate_target
from frisk.core.baseline import (
    Baseline,
    BaselineError,
    apply_baseline,
    finding_key,
    load_baseline,
    render_baseline,
)
from frisk.core.clientconfig import ConfigError, ConfiguredServer, parse_client_config
from frisk.core.detectors import ALL_DETECTORS
from frisk.core.engine import run_detectors
from frisk.core.models import Finding, Inventory, Severity
from frisk.core.report import render_human, render_json
from frisk.core.sanitize import c0_escape
from frisk.core.sarif import render_sarif
from frisk.core.score import Assessment, assess, exit_code, parse_fail_on
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
    parser.add_argument("--version", action="version", version=f"frisk {__version__}")
    sub = parser.add_subparsers(dest="command")

    for name, help_text in (
        ("scan", "connect, enumerate, and risk-score an MCP server"),
        ("verify", "re-enumerate and diff against a frisk.lock baseline (rug-pull check)"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument(
            "target",
            nargs="?",
            help="stdio command, or an http(s):// URL for a remote server",
        )
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

        p.add_argument(
            "--quiet",
            action="store_true",
            help="suppress warnings on stderr; the report and exit code are unchanged",
        )

    scan = sub.choices["scan"]
    scan.add_argument("--format", choices=["human", "json", "sarif"], default="human")
    scan.add_argument("--no-lock", action="store_true", help="do not write a frisk.lock")
    scan.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help=(
            "lowest severity that exits 2 (default: high). Moves the exit code only — "
            "every finding is still reported"
        ),
    )
    scan.add_argument(
        "--baseline",
        metavar="PATH",
        help="accepted-finding baseline; matching findings are reported but do not gate",
    )
    scan.add_argument(
        "--config",
        metavar="PATH",
        help=(
            "scan every server declared in an MCP client config "
            "(claude_desktop_config.json / .mcp.json) instead of a single target"
        ),
    )
    scan.add_argument(
        "--write-baseline",
        metavar="PATH",
        help="record this scan's findings as an accepted baseline, then exit 0",
    )

    return parser


class UsageError(Exception):
    """The command line is not what the user meant. Loud, with the fix in the message."""


def _known_option_strings(parser: argparse.ArgumentParser) -> set[str]:
    """Every option string frisk itself defines, subcommands included.

    Derived from the parser rather than listed, so adding a flag cannot leave the check
    behind (Pattern 26). The top-level parser only owns ``-h``; the real flags live on the
    subparsers, which hang off the subparsers action's ``choices``.
    """
    options: set[str] = set()
    stack = [parser]
    while stack:
        current = stack.pop()
        for action in current._actions:  # noqa: SLF001 — argparse exposes no public accessor
            options.update(action.option_strings)
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                stack.extend(
                    p for p in choices.values() if isinstance(p, argparse.ArgumentParser)
                )
    return options


def _reject_swallowed_options(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse frisk's own flags when they appear AFTER the target (R6 applied to argv).

    `args.args` is `argparse.REMAINDER`, so everything after the target goes to the child.
    That is what lets `frisk scan npx -y pkg --verbose` work, but it also meant
    `frisk scan srv --format json` silently produced a HUMAN report: a CI job parsing that
    output gets prose and no error. Anything that looks like one of ours is a mistake worth
    stopping for.

    `--` is the escape hatch, with the usual meaning: everything after it is the child's,
    even if it collides with a frisk flag.
    """
    passthrough = args.args.index("--") if "--" in args.args else len(args.args)
    ours = _known_option_strings(parser)
    for stray in (a for a in args.args[:passthrough] if a.split("=", 1)[0] in ours):
        raise UsageError(
            f"{stray!r} came after the target, so it went to the server instead of frisk. "
            f"frisk's own options go BEFORE the target: "
            f"frisk {args.command} {stray} … <target> [server args]. "
            f"If {stray!r} really is meant for the server, put it after a bare --."
        )


def _build_target(args: argparse.Namespace) -> Target:
    target = args.target
    if target.startswith(("http://", "https://")):
        token = os.environ.get(args.auth_env) if args.auth_env else None
        if token and target.startswith("http://"):
            _warn(
                args,
                f"sending the {args.auth_env} bearer token over plaintext http:// — it is "
                "readable by anything on the path. Use https:// unless this is a loopback "
                "address you control.",
            )
        return RemoteTarget(url=target, auth_token=token, transport=args.transport)
    # stdio: env is intentionally empty — the sandbox layers a benign allowlist on top and
    # forces a fake HOME, so the untrusted server never inherits frisk's own secrets (S3).
    stdio_args = [a for a in args.args if a != "--"]
    # env is empty for a hand-typed target: the sandbox layers a benign allowlist on top and
    # forces a fake HOME, so the untrusted server never inherits frisk's own secrets (S3).
    # A --config entry is different — its `env` is exactly what the CLIENT would pass, so
    # withholding it would scan a server in a state it never actually runs in.
    declared = getattr(args, "declared_env", None) or {}
    return StdioTarget(command=target, args=stdio_args, env=declared, cwd=os.getcwd())


def _warn(args: argparse.Namespace, message: str) -> None:
    """Warnings go to stderr unless `--quiet` (R35).

    `--quiet` never touches stdout or the exit code: silencing the diagnosis of a degraded
    sandbox is a choice a piping caller can make, silencing the VERDICT is not.
    """
    if not getattr(args, "quiet", False):
        print(f"warning: {message}", file=sys.stderr)


def _enumerate(args: argparse.Namespace) -> tuple[Inventory, list[Finding]]:
    """Sandbox (for stdio) then enumerate; returns the Inventory plus honeypot findings
    (R24). Raises ConnectorError on any failure (R6). Remote targets have no sandbox and
    therefore no honeypot — their findings list is always empty."""
    target = _build_target(args)
    if isinstance(target, StdioTarget):
        options = SandboxOptions(enabled=not args.no_sandbox, timeout_seconds=args.timeout)
        sandboxed = prepare_stdio(target, options)
        for warning in sandboxed.warnings:
            _warn(args, warning)
        if sandboxed.decoys is not None and not sandboxed.decoys.atime_reliable:
            # Degraded, not disabled: tamper + canary-exfiltration detection still work.
            _warn(
                args,
                "filesystem does not update atime on read — honeypot decoy-read detection "
                "is degraded (tamper and exfiltration detection still active)",
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
    sandboxed.cleanup()


def _load_baseline(path: str) -> Baseline:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        # Fail loudly: a baseline that quietly reads as empty turns the gate off without
        # saying so, which is the worst outcome available here (R6).
        raise UsageError(f"cannot read baseline {path}: {type(exc).__name__}") from None
    return load_baseline(text)


def _target_args_for(args: argparse.Namespace, server: ConfiguredServer) -> argparse.Namespace:
    """A per-server copy of the parsed args, so one config entry scans exactly like a
    single target would — same sandbox, same timeout, same honeypot."""
    per = argparse.Namespace(**vars(args))
    per.target = server.url if server.is_remote else server.command
    per.args = list(server.args)
    per.declared_env = dict(server.env)
    per.config = None
    return per


def _scan_config(args: argparse.Namespace) -> int:
    """Scan every server a client config declares (R36).

    One server failing to enumerate does NOT abort the others: the point of this mode is a
    picture of the whole setup, and a single broken entry must not hide the state of the
    rest. A failure is reported as a failed entry and gates the exit code (R6) — it is never
    quietly treated as clean.
    """
    try:
        text = Path(args.config).read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"cannot read config {args.config}: {type(exc).__name__}") from None
    servers = parse_client_config(text)

    baseline = _load_baseline(args.baseline) if args.baseline else None
    fail_on = parse_fail_on(args.fail_on)
    worst = 0
    sections: list[str] = []

    for server in servers:
        header = f"═══ {c0_escape(server.name)} ═══"
        if server.disabled:
            sections.append(f"{header}\ndisabled in the config — not scanned\n")
            continue
        per = _target_args_for(args, server)
        try:
            inventory, honeypot = _enumerate(per)
        except ConnectorError as exc:
            # Reported, not fatal, and it still gates: "could not be assessed" is never
            # the same as "clean".
            sections.append(f"{header}\nERROR: {exc}\n")
            worst = max(worst, EXIT_OPERATIONAL_ERROR)
            continue
        findings = run_detectors(inventory, ALL_DETECTORS) + honeypot
        if baseline is not None:
            split = apply_baseline(findings, baseline)
            gating, accepted, stale = split.gating, split.accepted, split.stale
        else:
            gating, accepted, stale = findings, [], []
        assessment = assess(gating)
        worst = max(worst, exit_code(assessment, fail_on))
        sections.append(
            header
            + "\n"
            + render_human(
                inventory,
                gating,
                assessment,
                accepted=accepted,
                stale=stale,
                fail_on=args.fail_on,
            )
        )

    sys.stdout.write(
        f"frisk — {len(servers)} server{'' if len(servers) == 1 else 's'} from "
        f"{c0_escape(args.config)}\n\n" + "\n".join(sections)
    )
    return worst


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.config:
        if args.target:
            raise UsageError(
                "give either a target or --config, not both — --config already says which "
                "servers to scan"
            )
        if args.format != "human":
            raise UsageError(f"--config currently supports --format human, not {args.format!r}")
        return _scan_config(args)
    if not args.target:
        raise UsageError("no target given: frisk scan <command-or-url>, or --config <path>")

    inventory, honeypot_findings = _enumerate(args)
    all_findings = run_detectors(inventory, ALL_DETECTORS) + honeypot_findings

    if args.write_baseline:
        # Writing a baseline is an explicit act of acceptance, so it reports what it accepted
        # and exits 0 rather than also gating on the very findings it just recorded.
        try:
            Path(args.write_baseline).write_text(
                render_baseline(all_findings), encoding="utf-8"
            )
        except OSError as exc:
            raise UsageError(
                f"cannot write baseline {args.write_baseline}: {type(exc).__name__}"
            ) from None
        accepted_keys = {finding_key(f) for f in all_findings}
        print(
            f"wrote baseline: {args.write_baseline} "
            f"({len(accepted_keys)} accepted finding{'' if len(accepted_keys) == 1 else 's'})",
            file=sys.stderr,
        )
        return 0

    baseline = _load_baseline(args.baseline) if args.baseline else None
    if baseline is not None:
        split = apply_baseline(all_findings, baseline)
        gating, accepted, stale = split.gating, split.accepted, split.stale
    else:
        gating, accepted, stale = all_findings, [], []

    assessment: Assessment = assess(gating)
    fail_on = parse_fail_on(args.fail_on)
    renderer = {"json": render_json, "sarif": render_sarif}.get(
        args.format, render_human
    )
    sys.stdout.write(
        renderer(
            inventory,
            gating,
            assessment,
            accepted=accepted,
            stale=stale,
            fail_on=args.fail_on,
        )
    )
    if not args.no_lock:
        try:
            write_lock(args.lock, inventory)
            if args.format == "human" and not args.quiet:
                print(f"\nwrote lockfile: {args.lock}", file=sys.stderr)
        except OSError as exc:
            # The verdict is the primary output; a failed lockfile write is a warning, not a
            # crash — and must not mask the risk exit code.
            _warn(args, f"could not write lockfile {args.lock}: {type(exc).__name__}")
    return exit_code(assessment, fail_on)


def _honeypot_line(f: Finding) -> str:
    """One stderr line per honeypot finding. item_ref can embed a server-controlled tool
    name (canary-in-raw-bytes branch), so everything is C0-escaped before hitting the
    terminal (R15) — this is the only Finding sink outside the core renderers."""
    return f"honeypot: [{f.severity.name}] {c0_escape(f.item_ref)} — {c0_escape(f.message)}"


def _cmd_verify(args: argparse.Namespace) -> int:
    if not args.target:
        raise UsageError("no target given: frisk verify <command-or-url>")
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
        _reject_swallowed_options(parser, args)
        if args.command == "scan":
            return _cmd_scan(args)
        return _cmd_verify(args)
    except (ConnectorError, LockError, UsageError, BaselineError, ConfigError) as exc:
        # Fail loud, never "clean": a specific, actionable error and a non-zero exit (R6).
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except Exception as exc:  # noqa: BLE001 — last line of the CI contract, see below
        # An uncaught exception would exit 1, and 1 is the code for "warnings" (R18) — a
        # crash would read to CI as a soft pass. Only the exception TYPE is printed: the
        # traceback can carry target bytes (Pattern 11).
        print(
            f"error: frisk failed unexpectedly ({type(exc).__name__}) — the target was NOT "
            "assessed; treat this as a failed scan, not a clean one",
            file=sys.stderr,
        )
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    sys.exit(main())
