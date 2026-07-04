"""Behavioral honeypot (R24): decoy credentials in the sandbox fake HOME.

Three mechanisms, all emitting standard core Findings under detector id ``D8`` so they flow
through the existing score/report/exit-code pipeline:

1. **seed_decoys** — plant realistic-shaped fake credential files, each embedding a unique
   per-scan canary token. atime is pinned to epoch (below mtime) so even a relatime-style
   mount updates it on the first read.
2. **inspect_decoys** — after enumeration, a stat diff against the seeded baseline: an
   advanced atime means the server read a decoy; a changed mtime/size or a missing file
   means it tampered with one.
3. **scan_for_canary** — the canary appearing in the enumerated Inventory is an
   exfiltration attempt via the MCP channel (the only exfil path the seatbelt leaves open).

This module lives in the sandbox package, not ``frisk.core``: it touches the filesystem, and
the detector core must stay pure so the Pyodide playground runs it unchanged (R23, N1).

Evidence never includes decoy file contents — paths and categories only (S3). The decoy
values are fake, but report output must not train readers to expect credential material in it.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

DETECTOR_ID = "D8"

# Canary: pure hex so it drops invisibly into any credential-shaped slot (PEM body, AWS
# secret key, password field). Uniqueness per scan is what makes a match meaningful.
_CANARY_BYTES = 20

# Decoy files seeded under the fake HOME. Templates are realistic-shaped so a thieving
# server has no cheap way to distinguish them from the real thing; `{canary}` lands where
# the secret material would be.
_DECOY_TEMPLATES: dict[str, str] = {
    ".ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
        "{canary}AAAAB3NzaC1yc2EAAAADAQABAAABgQDJf3lLaP7q4WZk9c1sYm3P\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    ".aws/credentials": (
        "[default]\n"
        "aws_access_key_id = AKIA{canary_upper16}\n"
        "aws_secret_access_key = {canary}\n"
        "region = us-east-1\n"
    ),
    ".netrc": ("machine github.com\nlogin deploy\npassword {canary}\n"),
    ".config/gh/hosts.yml": (
        "github.com:\n    oauth_token: gho_{canary}\n    user: deploy\n    git_protocol: https\n"
    ),
}

DECOY_RELPATHS: tuple[str, ...] = tuple(_DECOY_TEMPLATES)


@dataclass(frozen=True)
class DecoyBaseline:
    """Stat snapshot taken at seed time; the reference for the post-enumeration diff."""

    atime_ns: int
    mtime_ns: int
    size: int


@dataclass(frozen=True)
class DecoySet:
    home: Path
    canary: str
    baselines: dict[str, DecoyBaseline]  # relpath -> baseline
    # False when the filesystem does not update atime on read (probed at seed time). Access
    # detection is then degraded — callers must warn, never silently downgrade (R4a spirit).
    atime_reliable: bool


def seed_decoys(fake_home: Path) -> DecoySet:
    """Plant decoy credentials under ``fake_home`` and record their stat baselines."""
    canary = secrets.token_hex(_CANARY_BYTES)
    subs = {"canary": canary, "canary_upper16": canary[:16].upper()}
    baselines: dict[str, DecoyBaseline] = {}
    for relpath, template in _DECOY_TEMPLATES.items():
        path = fake_home / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(template.format(**subs), encoding="utf-8")
        path.chmod(0o600)  # credential-store permissions, part of looking real
        baselines[relpath] = _pin_atime(path)
    return DecoySet(
        home=fake_home,
        canary=canary,
        baselines=baselines,
        atime_reliable=_probe_atime(fake_home),
    )


def _pin_atime(path: Path) -> DecoyBaseline:
    """Set atime to epoch (keeping mtime) and return the resulting baseline."""
    st = path.stat()
    os.utime(path, ns=(0, st.st_mtime_ns))
    st = path.stat()
    return DecoyBaseline(atime_ns=st.st_atime_ns, mtime_ns=st.st_mtime_ns, size=st.st_size)


def _probe_atime(fake_home: Path) -> bool:
    """Does this filesystem update atime on read? Probe with a throwaway file."""
    probe = fake_home / ".frisk-atime-probe"
    try:
        probe.write_text("probe", encoding="utf-8")
        os.utime(probe, ns=(0, probe.stat().st_mtime_ns))
        probe.read_bytes()
        return probe.stat().st_atime_ns > 0
    except OSError:
        return False
    finally:
        probe.unlink(missing_ok=True)
