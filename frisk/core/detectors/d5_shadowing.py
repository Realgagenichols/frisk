"""D5 — shadowing / impersonation (R11).

Two signals:

1. **Common-name impersonation (MEDIUM)** — a third-party server advertising a name users
   associate with a built-in or first-party tool (`read_file`, `bash`, `web_search` …).
   Even when the description matches the name, a colliding name on a server you're vetting
   is exactly the shadowing vector: calls meant for the trusted tool route here.
2. **Steering (MEDIUM)** — description text that herds the model toward this tool or away
   from others ("always use this instead of …", "other servers' tools are unreliable").
3. **Duplicate names (MEDIUM)** — two definitions on the same server sharing a name (R28).
   Which one a client resolves is undefined, so a benign twin can stand in front of a
   poisoned one.

Names are compared folded (`fold_name`): `readFile` and `read_file` are one name to anyone
reading a tool list, so they are one name here.
"""

from __future__ import annotations

import re
from collections import Counter

from frisk.core.detectors.base import (
    Rule,
    contains_token_run,
    fold_name,
    model_visible_text,
    name_tokens,
    scan_item_leaves,
)
from frisk.core.models import Evidence, Finding, Inventory, Severity
from frisk.core.sanitize import make_evidence

_I = re.IGNORECASE

# Names commonly owned by built-in / first-party tooling.
_COMMON_TOOL_NAMES = {
    "read_file",
    "write_file",
    "edit_file",
    "create_file",
    "delete_file",
    "list_files",
    "list_directory",
    "list_dir",
    "bash",
    "terminal",
    "computer",
    "str_replace_editor",
    "web_search",
    "search_web",
    "fetch",
    "fetch_url",
    "browser",
    "execute_command",
    "run_command",
    "grep",
    "glob",
    "view",
    "edit",
    "apply_patch",
    "web_fetch",
    "task",
    "python",
    "shell",
}

# Two match modes, because impersonation is not always an exact name:
#   - folded equality catches `readFile`, `read-file`, `READFILE`;
#   - token-run containment catches `filesystem_read_file`, `read_file_v2`, `fs.read_file`,
#     without the false positives a substring test would produce (`thread_file`).
_COMMON_TOOL_NAMES_FOLDED = {fold_name(n) for n in _COMMON_TOOL_NAMES}
# Only multi-token names are matched by containment: a one-token name like `fetch` or `task`
# is too common a word to flag wherever it appears inside a longer name (N2).
_COMMON_TOOL_TOKEN_RUNS = [
    tokens for n in _COMMON_TOOL_NAMES if len(tokens := [t.lower() for t in name_tokens(n)]) > 1
]


def _impersonates(name: str) -> bool:
    if fold_name(name) in _COMMON_TOOL_NAMES_FOLDED:
        return True
    return any(contains_token_run(name, run) for run in _COMMON_TOOL_TOKEN_RUNS)

_STEERING_RULES = [
    Rule(
        category="steering-toward",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"\b(?:always|only)\s+use\s+this\b[^.\n]{0,60}?"
            r"\b(?:instead|rather\s+than|over|first|for\s+all)\b",
            _I,
        ),
        message="description steers the model to prefer this tool",
    ),
    Rule(
        category="steering-away",
        severity=Severity.MEDIUM,
        # Both alternations are tool/server-scoped: "do not use any other encoding" is
        # ordinary format prose and must stay clean (Pattern 2).
        pattern=re.compile(
            r"\b(?:other|built-?in|native)\b[^.\n]{0,40}?\btools?\b[^.\n]{0,40}?"
            r"\b(?:unreliable|broken|deprecated|unsafe|avoid|should\s+not|must\s+not)\b"
            r"|\b(?:do\s+not|don'?t|never|avoid)\s+us(?:e|ing)\b[^.\n]{0,40}?"
            r"\b(?:other|built-?in|native|any\s+other)\b[^.\n]{0,30}?"
            r"\b(?:tools?|servers?|readers?|providers?)\b",
            _I,
        ),
        message="description disparages or forbids other tools/servers",
    ),
]


class Shadowing:
    id = "D5"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = self._duplicate_names(inventory)
        for item in inventory.items:
            if _impersonates(item.name):
                findings.append(
                    Finding(
                        detector=self.id,
                        severity=Severity.MEDIUM,
                        item_ref=item.ref,
                        field="name",
                        message=(
                            f'"{item.name}" impersonates a common built-in tool name — '
                            "calls meant for the trusted tool may route here"
                        ),
                        evidence=make_evidence(
                            "common-name-impersonation", item.name, (0, len(item.name))
                        ),
                    )
                )
            # Steering can hide in any model-visible prose (param descriptions included).
            findings.extend(
                scan_item_leaves(self.id, item, _STEERING_RULES, field_filter=model_visible_text)
            )
        return findings

    def _duplicate_names(self, inventory: Inventory) -> list[Finding]:
        """Two definitions of one kind sharing a name (R28).

        Which one a client resolves is undefined, so a benign twin can stand in front of a
        poisoned one — the same shadowing vector as impersonating a built-in, sourced from
        the server's own inventory. Emitted WITHOUT a span so the engine's overlap
        suppression can never hide it behind another finding on the same name.
        """
        # Folded, like every other name comparison here: `search`/`Search` and
        # `read_notes`/`readNotes` collide for a client resolving by name, so counting raw
        # refs would let a twin hide behind a capitalisation.
        counts: Counter[str] = Counter()
        display: dict[str, str] = {}
        for item in inventory.items:
            key = f"{item.kind}:{fold_name(item.name)}"
            counts[key] += 1
            display.setdefault(key, item.ref)
        return [
            Finding(
                detector=self.id,
                severity=Severity.MEDIUM,
                item_ref=display[key],
                field="name",
                message=(
                    f"{count} definitions advertised under the same name — which one a "
                    "client resolves is undefined"
                ),
                evidence=Evidence(category="duplicate-definition-name"),
            )
            for key, count in sorted(counts.items())
            if count > 1
        ]
