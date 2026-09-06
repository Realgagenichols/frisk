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

    `payload` is the **complete** advertised definition, and it — not the three named
    attributes — is what detectors scan. MCP tools carry far more model-visible prose than
    `description`: `title`, `annotations.title`, `outputSchema`, `icons`, `_meta`; resources
    carry `uri` and `mimeType`. Retaining only the named fields let an attacker relocate a
    payload one key over and score zero findings. `name` / `description` / `input_schema`
    remain first-class because structural rules (D3, D4) index into them directly.
    """

    kind: ItemKind
    name: str
    description: str | None
    input_schema: dict[str, Any] | None
    raw_bytes: bytes
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        """Stable human/lock reference, e.g. ``tool:get_weather``.

        A resource with no `name` takes its name from its `uri`, and a URI can embed a
        password or an api-key query parameter — which the ref then carries into every
        report line AND into `frisk.lock` on disk. Credentials are masked here, at the one
        place every sink reads from (S3, Pattern 29). The hash is computed from `raw_bytes`,
        not from the ref, so masking cannot weaken rug-pull detection.
        """
        from frisk.core.sanitize import redact_url_secrets

        return f"{self.kind}:{redact_url_secrets(self.name)}"


@dataclass
class Inventory:
    """The full normalized set of definitions enumerated from a target (R2, R5)."""

    items: list[Item] = field(default_factory=list)
    # Raw server identity metadata (name/version/instructions) for D7 hygiene checks (R16).
    server_info: dict[str, Any] = field(default_factory=dict)
    # False when the input channel could not carry serverInfo at all (e.g. a pasted bare
    # tools/list, R21). D7 then skips the missing-identity check: "not provided by the
    # channel" is not evidence of "not provided by the server" (Pattern 2). The CLI
    # connector always sees the initialize result, so it always leaves this True.
    server_info_known: bool = True


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
    """Yield ``(field_path, raw_str)`` for every string the server advertised for this item.

    ``name`` and ``description`` are yielded first under their bare paths (stable references
    that predate the payload walk); every remaining payload key is then walked, so
    ``title``, ``annotations.title``, ``outputSchema``, ``uri``, ``icons[0].src`` and
    ``_meta`` are all scanned. There is no field allowlist to fall behind the MCP schema:
    whatever the server sends, a detector sees.

    Yields the **raw** strings — tabs, newlines, quotes and hidden characters intact — so
    detectors scan the representation their patterns were written for, never a ``json.dumps``
    blob whose escaping would change match semantics (cross-cutting Pattern 12).
    """
    yield ("name", item.name)
    if item.description is not None:
        yield ("description", item.description)
    for key in sorted(item.payload):
        if key in _PAYLOAD_KEYS_SCANNED_ELSEWHERE:
            continue
        # `arguments` is a prompt's scan surface only because ingest projects it into the
        # synthetic `inputSchema` below. On a TOOL or RESOURCE no such projection exists, so
        # skipping the key there would leave it entirely unscanned — and the SDK models are
        # `extra="allow"`, so a server can put one on any item kind.
        if key == "arguments" and item.kind is ItemKind.PROMPT:
            continue
        value = item.payload[key]
        # A resource with no `name` takes its name from `uri` (ingest.resource_item), which
        # would then be scanned once as `name` and again as `uri` — two identical findings
        # and a doubled risk score. Any payload string already yielded verbatim is skipped.
        if isinstance(value, str) and value in (item.name, item.description):
            continue
        yield from _walk(key, value)
    if item.input_schema is not None and "inputSchema" not in item.payload:
        # A prompt's schema is ingest's projection of `arguments`, not a payload key of its
        # own; so is the schema of an Item constructed directly rather than through ingest.
        yield from _walk("inputSchema", item.input_schema)


# `name`/`description` are emitted above under their bare paths — walking them again would
# double-report every finding in them.
_PAYLOAD_KEYS_SCANNED_ELSEWHERE = frozenset({"name", "description"})


def _walk(path: str, node: Any) -> Iterator[tuple[str, str]]:
    if isinstance(node, str):
        yield (path, node)
    elif isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}"
            # The key itself is a string leaf — property names matter for D3 (R9). It gets a
            # distinct `#key` path so every field_path resolves to exactly ONE string and
            # evidence offsets stay unambiguous (R12).
            yield (f"{child}#key", key)
            yield from _walk(child, value)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(f"{path}[{index}]", value)
    # numbers / bools / None carry no scannable text
