"""D5 — shadowing / impersonation (R11).

Two signals:

1. **Common-name impersonation (MEDIUM)** — a third-party server advertising a name users
   associate with a built-in or first-party tool (`read_file`, `bash`, `web_search` …).
   Even when the description matches the name, a colliding name on a server you're vetting
   is exactly the shadowing vector: calls meant for the trusted tool route here.
2. **Steering (MEDIUM)** — description text that herds the model toward this tool or away
   from others ("always use this instead of …", "other servers' tools are unreliable").
"""

from __future__ import annotations

import re

from frisk.core.detectors.base import Rule, scan_item_leaves
from frisk.core.models import Finding, Inventory, Severity
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
}

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
        pattern=re.compile(
            r"\b(?:other|built-?in|native)\b[^.\n]{0,40}?\btools?\b[^.\n]{0,40}?"
            r"\b(?:unreliable|broken|deprecated|unsafe|avoid|should\s+not|must\s+not)\b"
            r"|\b(?:do\s+not|don'?t|never|avoid)\s+us(?:e|ing)\b[^.\n]{0,40}?"
            r"\b(?:other|built-?in|native|any\s+other)\b",
            _I,
        ),
        message="description disparages or forbids other tools/servers",
    ),
]


class Shadowing:
    id = "D5"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            if item.name.lower() in _COMMON_TOOL_NAMES:
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
            findings.extend(
                scan_item_leaves(
                    self.id,
                    item,
                    _STEERING_RULES,
                    field_filter=lambda p: p == "description",
                )
            )
        return findings
