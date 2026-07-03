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
    """Fields whose free text the model reads as prose: name, description, and every
    schema `description` *value* (never `#key` leaves — those are schema-keyword noise,
    see tasks/lessons.md)."""
    return field_path in ("name", "description") or (
        field_path.endswith(".description") and not field_path.endswith("#key")
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
        for rule in rules:
            for match in rule.pattern.finditer(text):
                yield Finding(
                    detector=detector_id,
                    severity=rule.severity,
                    item_ref=item.ref,
                    field=field_path,
                    message=rule.message,
                    evidence=make_evidence(rule.category, text, match.span(), redact=redact),
                )
