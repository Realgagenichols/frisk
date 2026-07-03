"""Core data models: Inventory, Item, Finding — the detector core's shared vocabulary.

These are pure Python with no I/O so they run identically in the CLI and under Pyodide (R23).
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity. IntEnum so findings sort and `max()` gives the CI exit gate (R18)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # human-readable name in reports
        return self.name


class ItemKind(enum.StrEnum):
    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"


@dataclass(frozen=True)
class Item:
    """One normalized definition (tool/resource/prompt) from a target (R5).

    `raw_bytes` is the advertised JSON for this item exactly as received — kept verbatim for
    lockfile hashing and offset-accurate evidence (never re-serialized before hashing).
    """

    kind: ItemKind
    name: str
    description: str | None
    input_schema: dict[str, Any] | None
    raw_bytes: bytes

    @property
    def ref(self) -> str:
        """Stable human/lock reference, e.g. ``tool:get_weather``."""
        return f"{self.kind}:{self.name}"


@dataclass
class Inventory:
    """The full normalized set of definitions enumerated from a target (R2, R5)."""

    items: list[Item] = field(default_factory=list)
    # Raw server identity metadata (name/version/instructions) for D7 hygiene checks (R16).
    server_info: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    """Concrete, non-sensitive evidence for a finding (R12, S3).

    Never carries a raw secret value: `snippet` is C0-escaped and may be redacted; `offset`
    is the byte offset of the match within the field's UTF-8 encoding.
    """

    category: str
    offset: int | None = None
    span: tuple[int, int] | None = None
    snippet: str | None = None


@dataclass(frozen=True)
class Finding:
    """A single detected issue (R12)."""

    detector: str
    severity: Severity
    item_ref: str
    field: str
    message: str
    evidence: Evidence


def iter_string_leaves(item: Item) -> Iterator[tuple[str, str]]:
    """Yield ``(field_path, raw_str)`` for every string in an item.

    Walks ``name``, ``description``, and every string (both property key names and values) in
    ``input_schema``. Yields the **raw** strings — tabs, newlines, quotes and hidden characters
    intact — so detectors scan the representation their patterns were written for, never a
    ``json.dumps`` blob whose escaping would change match semantics (cross-cutting Pattern 12).
    """
    yield ("name", item.name)
    if item.description is not None:
        yield ("description", item.description)
    if item.input_schema is not None:
        yield from _walk("inputSchema", item.input_schema)


def _walk(path: str, node: Any) -> Iterator[tuple[str, str]]:
    if isinstance(node, str):
        yield (path, node)
    elif isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}"
            # The key itself is a string leaf — property names matter for D3 (R9).
            yield (child, key)
            yield from _walk(child, value)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(f"{path}[{index}]", value)
    # numbers / bools / None carry no scannable text
