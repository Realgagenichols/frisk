"""Build a sandboxed StdioTarget: seatbelt wrapper + fake HOME + scrubbed env + rlimits."""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from functools import lru_cache
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
    memory_mb: int = 2048  # 0 = do not ask for a memory limit (suppresses the warning)
    timeout_seconds: float = 30.0
    fake_home: Path | None = None  # caller-managed; created if omitted


@dataclass(frozen=True)
class RlimitSupport:
    """Which rlimits the wrapper shell can actually make bind on this platform."""

    cpu: bool
    memory: bool


@dataclass(frozen=True)
class SandboxResult:
    target: StdioTarget
    timeout_seconds: float
    fake_home: Path
    mode: str  # "seatbelt" | "fallback" | "disabled"
    warnings: tuple[str, ...] = ()
    # Honeypot decoys seeded in the fake HOME (R24); every prepared target carries them.
    decoys: DecoySet | None = None
    rlimits: RlimitSupport | None = None
    _cleanup: list[Path] = field(default_factory=list, repr=False)


def seatbelt_available() -> bool:
    """True when the macOS seatbelt sandbox (`sandbox-exec`) can be used."""
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


@lru_cache(maxsize=1)
def probe_rlimits() -> RlimitSupport:
    """Ask the wrapper shell whether the limits it sets actually bind (Pattern 16).

    `ulimit` reports success by not printing an error, which `2>/dev/null` then swallows —
    so for two releases the memory cap was set, ignored, and reported as containment. macOS
    does not implement `RLIMIT_AS` at all (`setrlimit` returns EINVAL there too), so the only
    way to know is to set a limit and read it back.
    """
    # Each probe reports on its own labelled line: a shell where `ulimit -v` errors and
    # prints nothing would otherwise shift the fields and take the working CPU limit down
    # with it.
    script = (
        "ulimit -t 3600 2>/dev/null; ulimit -v 1048576 2>/dev/null; "
        'echo "cpu=$(ulimit -t 2>/dev/null)"; echo "mem=$(ulimit -v 2>/dev/null)"'
    )
    try:
        completed = subprocess.run(
            ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return RlimitSupport(cpu=False, memory=False)
    reported = dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )

    def enforced(key: str) -> bool:
        value = reported.get(key, "").strip()
        return bool(value) and value != "unlimited"

    return RlimitSupport(cpu=enforced("cpu"), memory=enforced("mem"))


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
#
# This list is the sandbox's read confinement, so a gap in it is a readable credential. It
# previously covered .ssh/.aws/keychains and stopped — leaving `~/.claude.json` (which holds
# MCP server configs and their API tokens), shell history, browser profiles, and the whole of
# `~/.config` readable to the very servers frisk exists to distrust.
_SENSITIVE_HOME_SUBPATHS = (
    # Whole config tree: gcloud, gh, and every CLI that follows the XDG convention.
    # NOT `.local/share` alongside it: that is where uv, pipx, mise and asdf keep managed
    # INTERPRETERS, so denying it blocks the target's own runtime, not its secrets.
    ".config",
    # SSH / cloud / infra
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".azure",
    ".oci",
    ".terraform.d",
    ".databrickscfg",
    ".snowflake",
    ".chef",
    ".vault-token",
    ".ansible",
    # Agent / editor configs that carry provider keys and MCP server credentials
    ".claude",
    ".claude.json",
    ".codex",
    ".cursor",
    ".continue",
    # Package registries and language toolchains
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".gitconfig",
    ".git-credentials",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".bundle/config",
    ".composer/auth.json",
    ".m2/settings.xml",
    ".gradle/gradle.properties",
    # Databases and object stores
    ".pgpass",
    ".my.cnf",
    ".s3cfg",
    ".boto",
    ".rclone.conf",
    # Password managers
    ".op",
    ".password-store",
    # Shell startup files: where an exported API key actually lives, far more often than in
    # a credential store. Denying only history missed all of these.
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".bash_login",
    ".config/fish",
    # macOS credential, messaging, and browser stores
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/gcloud",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Slack",
    "Library/Application Support/Signal",
    "Library/Group Containers",
    "Library/Messages",
    "Library/Mail",
    "Library/Safari",
    "Library/Containers",
    "Library/Application Support/Code/User/globalStorage",
)
# NOT denied: ~/Documents, ~/Desktop, ~/Downloads. Denying them is tempting — frisk only ever
# runs initialize + list, so no honest server needs them — but servers themselves routinely
# live in those folders, and denying the tree the target is being run FROM breaks the scan
# with an "Operation not permitted" from the interpreter rather than anything diagnosable.
# Reads outside this denylist are permitted; README states that rather than implying
# otherwise.

# Path-shape denials that no subpath list can express: dotenv files (which live in whatever
# directory the scan runs from, not under HOME), direnv, and shell/REPL history files.
#
# Both patterns must match a FILE, never a path prefix. `/\.env($|\.)` denied the directory
# `.env` too, which broke any target in a `python -m venv .env` tree — the same shape of
# self-inflicted breakage as denying `~/.local/share`. The history pattern allows an
# undotted basename so fish's `~/.local/share/fish/fish_history` is covered.
_SENSITIVE_PATH_REGEXES = (
    r"/\.env($|\.[^/]*$)",
    r"/\.envrc$",
    r"/\.?[a-z0-9_]*_history$",
    r"/\.zsh_sessions/",
)


def _sbpl_string(value: str | Path) -> str:
    r"""Quote a value for a seatbelt policy literal.

    The profile is a program, and `$HOME` is user-controlled input to it. An unescaped `"`
    in a path would end the string and let the rest be read as policy (Pattern 11 applied to
    a policy language rather than a log line).
    """
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


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
    write_allows = " ".join(f"(subpath {_sbpl_string(p)})" for p in write_roots)
    secret_denials = [
        f"(deny file-read* (subpath {_sbpl_string(real_home / sub)}))"
        for sub in _SENSITIVE_HOME_SUBPATHS
    ]
    regex_denials = [
        f'(deny file-read* (regex #"{pattern}"))' for pattern in _SENSITIVE_PATH_REGEXES
    ]
    return "\n".join(
        [
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            # Block the real user's credential stores; `~` resolves to the empty decoy HOME.
            *secret_denials,
            *regex_denials,
            f"(allow file* (subpath {_sbpl_string(fake_home)}))",
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

    # rlimit wrapper: only limits this platform actually enforces are requested, so the
    # command line never implies containment the kernel will not deliver (R4a).
    rlimits = probe_rlimits()
    warnings: list[str] = []
    limits = []
    if rlimits.cpu:
        limits.append(f"ulimit -t {options.cpu_seconds} 2>/dev/null")
    if rlimits.memory and options.memory_mb:
        limits.append(f"ulimit -v {options.memory_mb * 1024} 2>/dev/null")
    if options.memory_mb and not rlimits.memory:
        warnings.append(
            "this platform does not enforce a memory rlimit (macOS has no working "
            "RLIMIT_AS) — the CPU limit and the hard wall-clock timeout still bound a "
            "runaway server, but its memory use is not capped"
        )
    if not rlimits.cpu:
        warnings.append("this platform does not enforce a CPU rlimit — only the wall-clock "
                        "timeout bounds a runaway server")
    rlimit_script = "; ".join([*limits, 'exec "$@"'])
    inner = [target.command, *target.args]

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
        warnings.insert(
            0,
            "seatbelt (sandbox-exec) unavailable — running with the lightweight fallback "
            "(scrubbed env + fake HOME + rlimits + timeout, NO network/filesystem seatbelt). "
            "Untrusted code is only weakly contained.",
        )
        command, args = _wrap_rlimits(rlimit_script, inner)

    sandboxed = StdioTarget(command=command, args=args, env=scrubbed, cwd=target.cwd)
    return SandboxResult(
        target=sandboxed,
        timeout_seconds=options.timeout_seconds,
        fake_home=fake_home,
        mode=mode,
        warnings=tuple(warnings),
        decoys=decoys,
        rlimits=rlimits,
        _cleanup=cleanup,
    )


def _wrap_rlimits(script: str, inner: list[str]) -> tuple[str, list[str]]:
    # sh -c 'script' sh <cmd> <args...>  →  $0=sh, $@=cmd args; `exec "$@"` runs it.
    return "/bin/sh", ["-c", script, "sh", *inner]
