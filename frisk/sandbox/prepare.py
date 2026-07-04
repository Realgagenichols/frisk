"""Build a sandboxed StdioTarget: seatbelt wrapper + fake HOME + scrubbed env + rlimits."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from frisk.connector.target import StdioTarget
from frisk.sandbox.honeypot import DecoySet, seed_decoys

# Benign ambient variables the untrusted child may keep; everything else is dropped so
# frisk's own secrets (AWS_*, OPENAI_API_KEY, …) never reach the target (S3).
_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TZ",
        "SHELL",
        "USER",
        "LOGNAME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONHASHSEED",
        "VIRTUAL_ENV",
    }
)


@dataclass(frozen=True)
class SandboxOptions:
    enabled: bool = True  # False → --no-sandbox (skip seatbelt layer only)
    cpu_seconds: int = 15
    memory_mb: int = 2048
    timeout_seconds: float = 30.0
    fake_home: Path | None = None  # caller-managed; created if omitted


@dataclass(frozen=True)
class SandboxResult:
    target: StdioTarget
    timeout_seconds: float
    fake_home: Path
    mode: str  # "seatbelt" | "fallback" | "disabled"
    warning: str | None = None
    # Honeypot decoys seeded in the fake HOME (R24); every prepared target carries them.
    decoys: DecoySet | None = None
    _cleanup: list[Path] = field(default_factory=list, repr=False)


def seatbelt_available() -> bool:
    """True when the macOS seatbelt sandbox (`sandbox-exec`) can be used."""
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def scrub_env(
    target_env: dict[str, str], fake_home: Path, ambient: dict[str, str]
) -> dict[str, str]:
    """Allowlist ambient env, layer the target's declared env on top, force HOME/TMPDIR."""
    scrubbed = {k: ambient[k] for k in _ENV_ALLOWLIST if k in ambient}
    scrubbed.update(target_env)  # the server's explicitly declared env is intentional
    scrubbed["HOME"] = str(fake_home)
    scrubbed["TMPDIR"] = str(fake_home / "tmp")
    return scrubbed


# Secret stores under the real HOME that the untrusted child must never read. We deny these
# specific subpaths rather than the whole HOME so the interpreter/project (which also live
# under HOME) still run; the fake-HOME env redirect handles bare `~` resolution.
_SENSITIVE_HOME_SUBPATHS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".azure",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "Library/Keychains",
    "Library/Application Support/gcloud",
)


def build_profile(fake_home: Path, real_home: Path) -> str:
    """A seatbelt policy: allow-by-default, then deny network, secret stores, and stray writes.

    Allow-default (rather than deny-default) keeps the profile robust across machines — a
    deny-default profile that still lets an arbitrary interpreter start is brittle. The
    denials enforce R4: no network, no reads of the real HOME's credential stores, and writes
    confined to the sandbox scratch + standard temp. Rule order matters: later rules win.
    """
    write_roots = [
        str(fake_home),
        "/private/tmp",
        "/tmp",
        "/private/var/folders",
        "/var/folders",
    ]
    write_allows = " ".join(f'(subpath "{p}")' for p in write_roots)
    secret_denials = [
        f'(deny file-read* (subpath "{real_home / sub}"))' for sub in _SENSITIVE_HOME_SUBPATHS
    ]
    return "\n".join(
        [
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            # Block the real user's credential stores; `~` resolves to the empty decoy HOME.
            *secret_denials,
            f'(allow file* (subpath "{fake_home}"))',
            # Confine writes: deny everywhere, then re-allow the scratch/temp roots + devnull.
            '(deny file-write* (subpath "/"))',
            f"(allow file-write* {write_allows} "
            '(literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr") '
            '(literal "/dev/dtracehelper") (literal "/dev/tty"))',
        ]
    )


def _make_fake_home(explicit: Path | None) -> tuple[Path, list[Path]]:
    cleanup: list[Path] = []
    if explicit is not None:
        home = explicit
    else:
        import tempfile

        home = Path(tempfile.mkdtemp(prefix="frisk-home-"))
        cleanup.append(home)
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    return home, cleanup


def prepare_stdio(
    target: StdioTarget,
    options: SandboxOptions,
    *,
    ambient: dict[str, str] | None = None,
) -> SandboxResult:
    """Transform a StdioTarget into a sandboxed one plus the wall-clock timeout to apply."""
    import os

    ambient = dict(os.environ) if ambient is None else ambient
    fake_home, cleanup = _make_fake_home(options.fake_home)
    # Seed honeypot decoys in every mode (R24) — the fake HOME exists even without seatbelt.
    decoys = seed_decoys(fake_home)
    scrubbed = scrub_env(target.env, fake_home, ambient)
    real_home = Path(ambient.get("HOME", str(Path.home())))

    # rlimit wrapper (portable subset): CPU seconds always, address space best-effort.
    mem_kb = options.memory_mb * 1024
    rlimit_script = (
        f"ulimit -t {options.cpu_seconds} 2>/dev/null; "
        f"ulimit -v {mem_kb} 2>/dev/null; "
        'exec "$@"'
    )
    inner = [target.command, *target.args]

    warning: str | None = None
    if not options.enabled:
        mode = "disabled"
        command, args = _wrap_rlimits(rlimit_script, inner)
    elif seatbelt_available():
        mode = "seatbelt"
        profile = build_profile(fake_home, real_home)
        wrapped_command, wrapped_args = _wrap_rlimits(rlimit_script, inner)
        command = "sandbox-exec"
        args = ["-p", profile, wrapped_command, *wrapped_args]
    else:
        mode = "fallback"
        warning = (
            "seatbelt (sandbox-exec) unavailable — running with the lightweight fallback "
            "(scrubbed env + fake HOME + rlimits + timeout, NO network/filesystem seatbelt). "
            "Untrusted code is only weakly contained."
        )
        command, args = _wrap_rlimits(rlimit_script, inner)

    sandboxed = StdioTarget(command=command, args=args, env=scrubbed, cwd=target.cwd)
    return SandboxResult(
        target=sandboxed,
        timeout_seconds=options.timeout_seconds,
        fake_home=fake_home,
        mode=mode,
        warning=warning,
        decoys=decoys,
        _cleanup=cleanup,
    )


def _wrap_rlimits(script: str, inner: list[str]) -> tuple[str, list[str]]:
    # sh -c 'script' sh <cmd> <args...>  →  $0=sh, $@=cmd args; `exec "$@"` runs it.
    return "/bin/sh", ["-c", script, "sh", *inner]
