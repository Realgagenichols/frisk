"""Shared machinery for regex-driven leaf-scanning detectors."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from frisk.core.models import Finding, Item, Severity, iter_string_leaves
from frisk.core.sanitize import make_evidence


@dataclass(frozen=True)
class Rule:
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


def model_visible_text(field_path: str) -> bool:
    """Fields whose free text the model reads: name, description, and EVERY string value
    inside the schema (`title`, `examples`, `default`, …) — the model receives the whole
    inputSchema JSON, so limiting prose rules to `.description` values leaves a trivial
    relocation bypass. Only `#key` leaves are excluded: those are schema-keyword noise
    (see tasks/lessons.md)."""
    return field_path in ("name", "description") or (
        field_path.startswith("inputSchema") and not field_path.endswith("#key")
    )


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
