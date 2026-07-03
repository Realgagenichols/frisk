"""D7 — metadata hygiene (R16).

Lower-severity signals: tool code sourced from a remote/unpinned location at call time,
and suspicious or missing server identity metadata. A docs link in a description is not a
remote-code signal — the rule needs a run/fetch verb coupled with a code noun (N2).
"""

from __future__ import annotations

import re

from frisk.core.detectors.base import Rule, model_visible_text, scan_item_leaves
from frisk.core.models import Evidence, Finding, Inventory, Severity

_I = re.IGNORECASE

_RULES = [
    Rule(
        category="remote-unpinned-code",
        severity=Severity.LOW,
        pattern=re.compile(
            r"\b(?:runs?|executes?|fetch(?:es)?|downloads?|loads?|installs?|pulls?)\b"
            r"[^.\n]{0,80}?\b(?:script|code|binary|package|plugin|executable)\b"
            r"|\b(?:latest|newest)\b[^.\n]{0,40}?\bfrom\s+https?://",
            _I,
        ),
        message="code sourced from a remote/unpinned location",
    ),
]


class MetadataHygiene:
    id = "D7"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            findings.extend(
                scan_item_leaves(self.id, item, _RULES, field_filter=model_visible_text)
            )
        findings.extend(self._check_server_identity(inventory))
        return findings

    def _check_server_identity(self, inventory: Inventory) -> list[Finding]:
        info = inventory.server_info
        missing = [k for k in ("name", "version") if not info.get(k)]
        if not missing:
            return []
        return [
            Finding(
                detector=self.id,
                severity=Severity.LOW,
                item_ref="(server)",
                field="serverInfo",
                message=f"server identity metadata missing: {', '.join(missing)}",
                evidence=Evidence(category="missing-server-identity"),
            )
        ]
