"""Accepted-finding baseline (R33) — the difference between a CI gate that survives and one
that gets deleted in its first week.

A real server produces findings that are correct and permanent. The official
`@modelcontextprotocol/server-filesystem` genuinely does advertise `read_file`, `write_file`,
`edit_file` and `list_directory`, so D5 genuinely does flag four impersonations. Without a
way to say "yes, I looked, that one is expected", the first honest server anyone gates on
makes the build red forever and the step gets removed.

The whole design turns on the KEY. A baseline entry is
``(detector, item_ref, field, evidence.category)``:

- **not the offset or span** — those move the moment a description is reworded, so an
  offset-keyed baseline goes stale on every cosmetic edit and teaches people to regenerate it
  blindly, which is how a real finding gets accepted by accident;
- **not a hash of the whole finding** — that includes the message text, so improving a
  detector's wording would silently un-accept every baselined finding;
- **not the item alone** — accepting "this tool is noisy" would suppress a *new* category of
  finding on that tool later, which is precisely the rug-pull frisk exists to catch.

Baselined findings are still reported. Suppressing them from view would make the report lie
about what the server advertises; only the exit-code decision changes.

Pure core, no I/O — the playground runs this unchanged (R23).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from frisk.core.models import Finding

BASELINE_VERSION = 1

FindingKey = tuple[str, str, str, str]


class BaselineError(Exception):
    """A malformed or unreadable baseline file. The message names the exact problem."""


def finding_key(finding: Finding) -> FindingKey:
    """The stable identity of a finding across rewordings and offset churn."""
    return (finding.detector, finding.item_ref, finding.field, finding.evidence.category)


@dataclass(frozen=True)
class Baseline:
    keys: frozenset[FindingKey]
    note: str | None = None


@dataclass
class BaselineResult:
    """What a baseline did to a scan."""

    gating: list[Finding] = field(default_factory=list)  # decide the exit code
    accepted: list[Finding] = field(default_factory=list)  # matched the baseline
    stale: list[FindingKey] = field(default_factory=list)  # in the baseline, not in the scan


def apply_baseline(findings: list[Finding], baseline: Baseline) -> BaselineResult:
    """Split findings into gating and accepted, and report entries that matched nothing.

    Stale entries are surfaced rather than ignored: an accepted finding that has since been
    FIXED should stop being accepted, or the baseline quietly grows into a list of permissions
    nobody has re-read (Pattern 27 — "absent" is a claim about the query you ran).
    """
    result = BaselineResult()
    matched: set[FindingKey] = set()
    for finding in findings:
        key = finding_key(finding)
        if key in baseline.keys:
            result.accepted.append(finding)
            matched.add(key)
        else:
            result.gating.append(finding)
    result.stale = sorted(baseline.keys - matched)
    return result


def render_baseline(findings: list[Finding], *, note: str | None = None) -> str:
    """Serialize accepted findings. Deterministic: this file is meant to be committed, and a
    baseline that reorders itself on every write is unreviewable in a diff.

    No timestamp, for the same reason — git already records when it changed, and a churning
    header trains reviewers to skim past the part that matters.
    """
    entries = sorted({finding_key(f) for f in findings})
    doc: dict[str, Any] = {
        "version": BASELINE_VERSION,
        "note": note
        or "Findings reviewed and accepted. Delete an entry to start failing on it again.",
        "findings": [
            {"detector": d, "item": i, "field": f, "category": c} for d, i, f, c in entries
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def load_baseline(text: str) -> Baseline:
    """Parse a baseline file. Fails loudly and specifically (R6) — a baseline that silently
    parses as empty would turn a gate off without saying so, which is the worst outcome
    available here."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
        ) from None
    if not isinstance(doc, dict):
        raise BaselineError(f"baseline must be a JSON object, got {type(doc).__name__}")
    version = doc.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"unsupported baseline version {version!r} (this frisk writes v{BASELINE_VERSION})"
        )
    raw = doc.get("findings")
    if not isinstance(raw, list):
        raise BaselineError("baseline is missing a 'findings' array")
    keys: set[FindingKey] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise BaselineError(f"findings[{index}] must be an object")
        try:
            key = (entry["detector"], entry["item"], entry["field"], entry["category"])
        except KeyError as exc:
            raise BaselineError(f"findings[{index}] is missing {exc.args[0]!r}") from None
        if not all(isinstance(part, str) for part in key):
            raise BaselineError(f"findings[{index}] fields must all be strings")
        keys.add(key)
    note = doc.get("note")
    return Baseline(keys=frozenset(keys), note=note if isinstance(note, str) else None)
