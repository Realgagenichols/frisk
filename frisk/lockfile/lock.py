"""frisk.lock: a hashed snapshot of every definition, and the verify diff (R14, R15).

The lockfile is line-framed text: a header, then one ``<sha256>  <escaped-ref>`` line per
definition. Writer and reader share ONE framing rule — split on explicit ``"\n"``, never
``str.splitlines()`` — so a definition name carrying U+2028/2029/0085 (which ``splitlines``
treats as a line break but ``"\n".join`` does not) round-trips correctly instead of
silently corrupting the baseline (cross-cutting Pattern 13). Refs are C0-escaped on write so
a name with a raw newline can never forge an extra lock line.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from frisk.core.models import Inventory, Item
from frisk.core.sanitize import c0_escape

LOCK_VERSION = 1
_HEADER = f"frisk-lock v{LOCK_VERSION}"
_HASH_LEN = 64  # sha256 hex
_SEP = "  "


class LockError(Exception):
    """A malformed or unreadable lockfile."""


def hash_item(item: Item) -> str:
    """SHA-256 of the canonical advertised bytes — newline-safe, encoding-safe (R5, R14)."""
    return hashlib.sha256(item.raw_bytes).hexdigest()


def _lock_key(ref: str) -> str:
    # C0-escaped so a ref can never contain a raw newline that would forge a lock line.
    return c0_escape(ref)


def build_lock_text(inventory: Inventory) -> str:
    lines = [_HEADER]
    for item in inventory.items:
        lines.append(f"{hash_item(item)}{_SEP}{_lock_key(item.ref)}")
    return "\n".join(lines) + "\n"


def write_lock(path: str | Path, inventory: Inventory) -> None:
    Path(path).write_text(build_lock_text(inventory), encoding="utf-8")


def read_lock(path: str | Path) -> dict[str, str]:
    """Parse a lockfile into ``{escaped_ref: hash}``. Splits on explicit ``"\n"`` (R15)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise LockError(f"cannot read lockfile {path}: {type(exc).__name__}") from None
    lines = text.split("\n")  # explicit framing — never splitlines() (Pattern 13)
    if not lines or lines[0] != _HEADER:
        raise LockError(f"not a frisk lockfile (bad header) in {path}")
    entries: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if len(line) < _HASH_LEN + len(_SEP):
            raise LockError(f"malformed lock line in {path}")
        entries[line[_HASH_LEN + len(_SEP) :]] = line[:_HASH_LEN]
    return entries


@dataclass(frozen=True)
class LockDiff:
    added: list[str]
    removed: list[str]
    mutated: list[str]

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed or self.mutated)


def diff_lock(locked: dict[str, str], inventory: Inventory) -> LockDiff:
    """Diff a live inventory against a lockfile baseline (R14)."""
    live = {_lock_key(item.ref): hash_item(item) for item in inventory.items}
    added = sorted(set(live) - set(locked))
    removed = sorted(set(locked) - set(live))
    mutated = sorted(ref for ref in set(locked) & set(live) if locked[ref] != live[ref])
    return LockDiff(added=added, removed=removed, mutated=mutated)


def render_diff(diff: LockDiff) -> str:
    """Render a verify diff. Refs are already C0-escaped from the lock key (R15)."""
    if not diff.changed:
        return "verify: OK — no changes since the lockfile.\n"
    lines = ["verify: DRIFT — definitions changed since the lockfile:"]
    lines += [f"  - removed  {ref}" for ref in diff.removed]
    lines += [f"  + added    {ref}" for ref in diff.added]
    lines += [f"  ~ mutated  {ref}" for ref in diff.mutated]
    return "\n".join(lines) + "\n"
