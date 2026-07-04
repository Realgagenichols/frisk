"""Lockfile / verify tests (R14, R15, Pattern 13)."""

import pytest

from frisk.core.models import Inventory, Item, ItemKind
from frisk.lockfile import (
    LockDiff,
    LockError,
    diff_lock,
    hash_item,
    read_lock,
    render_diff,
    write_lock,
)


def item(name="get_weather", desc="Gets weather.", raw=None) -> Item:
    raw_bytes = raw if raw is not None else f'{{"name":"{name}","description":"{desc}"}}'.encode()
    return Item(
        kind=ItemKind.TOOL, name=name, description=desc, input_schema=None, raw_bytes=raw_bytes
    )


def inv(*items) -> Inventory:
    return Inventory(items=list(items))


def test_write_then_read_round_trips(tmp_path):
    lock_path = tmp_path / "frisk.lock"
    inventory = inv(item("a"), item("b"))
    write_lock(lock_path, inventory)
    locked = read_lock(lock_path)
    assert set(locked) == {"tool:a", "tool:b"}
    assert locked["tool:a"] == hash_item(item("a"))


def test_unchanged_inventory_shows_no_drift(tmp_path):
    lock_path = tmp_path / "frisk.lock"
    inventory = inv(item("a"), item("b"))
    write_lock(lock_path, inventory)
    diff = diff_lock(read_lock(lock_path), inventory)
    assert not diff.changed


def test_mutated_description_reported_as_mutated(tmp_path):
    # R14 scenario: a changed tool description → reported mutated.
    lock_path = tmp_path / "frisk.lock"
    write_lock(lock_path, inv(item("a", desc="original")))
    diff = diff_lock(read_lock(lock_path), inv(item("a", desc="CHANGED")))
    assert diff.mutated == ["tool:a"]
    assert not diff.added and not diff.removed
    assert diff.changed


def test_added_and_removed_definitions_reported(tmp_path):
    lock_path = tmp_path / "frisk.lock"
    write_lock(lock_path, inv(item("a"), item("b")))
    diff = diff_lock(read_lock(lock_path), inv(item("a"), item("c")))
    assert diff.added == ["tool:c"]
    assert diff.removed == ["tool:b"]
    assert not diff.mutated


def test_render_diff_clean_and_dirty():
    assert "no changes" in render_diff(LockDiff([], [], []))
    out = render_diff(LockDiff(added=["tool:c"], removed=["tool:b"], mutated=["tool:a"]))
    assert "DRIFT" in out and "tool:a" in out and "tool:b" in out and "tool:c" in out


def test_bad_header_raises_lockerror(tmp_path):
    p = tmp_path / "frisk.lock"
    p.write_text("not a lockfile\n", encoding="utf-8")
    with pytest.raises(LockError):
        read_lock(p)


def test_missing_lockfile_raises_lockerror(tmp_path):
    with pytest.raises(LockError):
        read_lock(tmp_path / "does-not-exist.lock")


def test_name_with_unicode_line_separators_round_trips(tmp_path):
    # Pattern 13: a name containing U+2028/2029/0085 must NOT corrupt the line-framed lock.
    # splitlines() would break the ref across phantom lines; split("\n") keeps it intact.
    evil_name = "tool\u2028one\u2029two\u0085three"
    lock_path = tmp_path / "frisk.lock"
    write_lock(lock_path, inv(item(evil_name)))
    locked = read_lock(lock_path)
    # Exactly one entry survived, with its full name intact.
    assert len(locked) == 1
    # Unchanged inventory → no drift; a real change → detected as mutated (not corrupted).
    assert not diff_lock(locked, inv(item(evil_name))).changed
    assert diff_lock(locked, inv(item(evil_name, desc="changed"))).mutated


def test_name_with_raw_newline_cannot_forge_a_second_entry(tmp_path):
    # R15: a raw newline in a ref is C0-escaped, so it can't inject an extra lock line.
    lock_path = tmp_path / "frisk.lock"
    write_lock(lock_path, inv(item("a\nb\tc")))
    locked = read_lock(lock_path)
    assert len(locked) == 1  # one entry, not two
    assert "\\x0a" in next(iter(locked))  # newline visibly escaped
