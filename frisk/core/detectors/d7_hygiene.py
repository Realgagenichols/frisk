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
        # verb + code-noun alone is NOT enough — "executes the provided Python code in a
        # sandbox" is a legitimate server class. The rule additionally requires a remote /
        # unpinned coupling (URL, "at call time", "latest").
        # Requires BOTH a run/fetch verb + code noun AND a remote/unpinned source coupling.
        # "Returns the latest version of an npm package" has no exec verb → clean.
        pattern=re.compile(
            r"\b(?:runs?|executes?|fetch(?:es)?|downloads?|loads?|installs?|pulls?)\b"
            r"[^.\n]{0,80}?\b(?:script|code|binary|package|plugin|executable)\b"
            r"[^.\n]{0,60}?(?:https?://|\bat\s+call\s+time\b|\bremote\b|\blatest\b|\bnewest\b)"
            r"|\b(?:runs?|executes?|fetch(?:es)?|downloads?|loads?|installs?|pulls?)\b"
            r"[^.\n]{0,40}?\b(?:latest|newest)\b[^.\n]{0,40}?"
            r"\b(?:script|code|binary|package|plugin|executable)\b"
            r"|\b(?:latest|newest)\b[^.\n]{0,40}?\bfrom\s+https?://",
            _I,
        ),
        message="code sourced from a remote/unpinned location",
    ),
]

_UNPINNED_VERSIONS = {"latest", "dev", "head", "main", "master", "nightly"}


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
        findings: list[Finding] = []
        missing = [k for k in ("name", "version") if not info.get(k)]
        if missing and inventory.server_info_known:
            findings.append(
                Finding(
                    detector=self.id,
                    severity=Severity.LOW,
                    item_ref="(server)",
                    field="serverInfo",
                    message=f"server identity metadata missing: {', '.join(missing)}",
                    evidence=Evidence(category="missing-server-identity"),
                )
            )
        version = info.get("version")
        if isinstance(version, str) and version.lower() in _UNPINNED_VERSIONS:
            findings.append(
                Finding(
                    detector=self.id,
                    severity=Severity.LOW,
                    item_ref="(server)",
                    field="serverInfo.version",
                    message="server version is an unpinned moving target",
                    evidence=Evidence(category="unpinned-server-version"),
                )
            )
        return findings
