"""Sandbox (macOS) — bound the blast radius of running an untrusted stdio server (R4, R4a).

Layers, defense-in-depth:
- **seatbelt** (`sandbox-exec`): deny all network, deny the real `$HOME`, confine writes to
  the scratch/temp dirs.
- **throwaway fake `$HOME`**: reads of `~/.ssh` / `~/.aws` hit an empty decoy, never the
  user's real secrets. (The M3 honeypot seeds decoys here.)
- **scrubbed env**: the untrusted child inherits an allowlist of benign variables plus the
  target's own declared env — never frisk's ambient secrets.
- **CPU/memory rlimits + hard wall-clock timeout**: bound runaway resource use.

`--no-sandbox` disables the seatbelt layer; when `sandbox-exec` is unavailable frisk falls
back to the non-seatbelt layers with a printed warning — never a silent downgrade (R4a).
"""

from __future__ import annotations

from frisk.sandbox.prepare import (
    SandboxOptions,
    SandboxResult,
    prepare_stdio,
    scrub_env,
    seatbelt_available,
)

__all__ = [
    "SandboxOptions",
    "SandboxResult",
    "prepare_stdio",
    "scrub_env",
    "seatbelt_available",
]
