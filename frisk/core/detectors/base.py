"""Shared machinery for regex-driven leaf-scanning detectors."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from frisk.core.models import Finding, Item, Severity, iter_string_leaves
from frisk.core.sanitize import make_evidence


def fold_name(name: str) -> str:
    """Fold an identifier to letters+digits so separator and case style can't hide a match.

    `read_file`, `readFile`, `ReadFile`, `read-file` and `READFILE` are the same name to a
    user reading a tool list, so they must be the same name to a name-matching rule. Matching
    raw lowercase let `readFile` walk past D5's impersonation list and `callbackUrl` past
    D4's capability list.
    """
    return re.sub(r"[^a-z0-9]", "", name.lower())


@dataclass(frozen=True)
class Rule:
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


def model_visible_text(field_path: str) -> bool:
    """Every advertised string value is model-visible; only JSON key names are excluded.

    This is deliberately a denylist of ONE thing rather than an allowlist of field names. An
    allowlist has to be extended every time the MCP schema grows a field, and until it is,
    the un-listed field is a free relocation bypass — which is exactly how `title`,
    `annotations.title` and `outputSchema` went unscanned. `#key` leaves are the sole
    exclusion: they are JSON-Schema structural keywords (`type`, `properties`, …), noise that
    generic word patterns would match on every schema ever written (see tasks/lessons.md).
    Detectors that need key names read them structurally instead (D3, D4).
    """
    return not field_path.endswith("#key")


def scan_item_leaves(
    detector_id: str,
    item: Item,
    rules: list[Rule],
    *,
    field_filter: Callable[[str], bool],
    redact: bool = False,
) -> Iterator[Finding]:
    """Run every rule over every string leaf that passes ``field_filter``.

    Overlapping hits across rules/detectors are resolved later by the engine's
    suppression pass (R12) — a detector just reports everything it sees.
    """
    for field_path, text in iter_string_leaves(item):
        if not field_filter(field_path):
            continue
        yield from scan_text(detector_id, item.ref, field_path, text, rules, redact=redact)


def scan_text(
    detector_id: str,
    item_ref: str,
    field_path: str,
    text: str,
    rules: list[Rule],
    *,
    redact: bool = False,
) -> Iterator[Finding]:
    """Run rules over one raw string — also used for server-level metadata like
    ``serverInfo.instructions``, which is model-visible but not an item leaf."""
    for rule in rules:
        for match in rule.pattern.finditer(text):
            yield Finding(
                detector=detector_id,
                severity=rule.severity,
                item_ref=item_ref,
                field=field_path,
                message=rule.message,
                evidence=make_evidence(rule.category, text, match.span(), redact=redact),
            )
