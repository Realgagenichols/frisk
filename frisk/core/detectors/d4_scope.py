"""D4 — capability / scope mismatch (R10).

Two signals:

1. **Mismatch (MEDIUM)** — a tool requests a shell/file/network capability parameter while
   its stated purpose (name + description) never declares that capability. A `get_weather`
   tool taking a `command` param is lying about its scope.
2. **Primitive advertisement (INFO)** — the server exposes an exec/file primitive at all
   (`run_shell`, `write_file`, …). Honest, but inherently high-privilege — worth a note,
   never a MEDIUM: an honestly-described shell tool must not be over-flagged (N2).
"""

from __future__ import annotations

import re

from frisk.core.models import Finding, Inventory, Item, Severity
from frisk.core.sanitize import make_evidence

_I = re.IGNORECASE


class _Capability:
    def __init__(self, name: str, param_names: set[str], desc_pattern: str, purpose: str):
        self.name = name
        self.param_names = param_names
        self.desc_pattern = re.compile(desc_pattern, _I)
        self.purpose_pattern = re.compile(purpose, _I)


_CAPABILITIES = [
    _Capability(
        "exec",
        {"command", "cmd", "shell", "exec", "script", "eval", "code"},
        r"shell\s+command|command\s+to\s+(?:run|execute)|shell\s+to\s+invoke",
        r"shell|command|execut|\brun\b|script|terminal|\beval\b|\bcode\b",
    ),
    _Capability(
        "file",
        {"filepath", "file_path", "filename", "file_name", "path"},
        r"path\s+(?:to|of)\s+.{0,30}?(?:file|director)",
        r"\bfiles?\b|\bread|\bwrit|\bsave|\bload|document|workspace|director|folder|path",
    ),
    _Capability(
        "network",
        {"url", "endpoint", "webhook", "callback_url", "uri"},
        r"url\s+to\s+(?:fetch|post|send|call)",
        r"\burl\b|\bhttp|fetch|request|\bweb\b|\bapi\b|endpoint|link|brows|download|upload",
    ),
]

_PRIMITIVE_NAME = re.compile(
    r"^(?:run|exec(?:ute)?|eval)_?(?:shell|command|cmd|code|script)?$"
    r"|^(?:read|write|delete|create)_?file$"
    r"|^shell$",
    _I,
)
_PRIMITIVE_DESC = re.compile(r"executes?\s+(?:a\s+|arbitrary\s+)?shell\s+command", _I)


class ScopeMismatch:
    id = "D4"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            findings.extend(self._scan_item(item))
        return findings

    def _scan_item(self, item: Item) -> list[Finding]:
        findings: list[Finding] = []
        purpose_text = f"{item.name} {item.description or ''}"

        # Signal 2: exec/file primitive advertised at all (INFO).
        if _PRIMITIVE_NAME.search(item.name) or _PRIMITIVE_DESC.search(item.description or ""):
            findings.append(
                Finding(
                    detector=self.id,
                    severity=Severity.INFO,
                    item_ref=item.ref,
                    field="name",
                    message="server advertises an exec/file primitive — inherently high-privilege",
                    evidence=make_evidence("capability-primitive", item.name, (0, len(item.name))),
                )
            )

        # Signal 1: capability param without a declared matching purpose (MEDIUM).
        props = (item.input_schema or {}).get("properties")
        if not isinstance(props, dict):
            return findings
        for prop_name, spec in props.items():
            spec = spec if isinstance(spec, dict) else {}
            prop_desc = spec.get("description", "")
            prop_desc = prop_desc if isinstance(prop_desc, str) else ""
            for cap in _CAPABILITIES:
                requests_cap = prop_name.lower() in cap.param_names or cap.desc_pattern.search(
                    prop_desc
                )
                if requests_cap and not cap.purpose_pattern.search(purpose_text):
                    findings.append(
                        Finding(
                            detector=self.id,
                            severity=Severity.MEDIUM,
                            item_ref=item.ref,
                            field=f"inputSchema.properties.{prop_name}#key",
                            message=(
                                f'tool requests {cap.name} capability via "{prop_name}" but its '
                                f"stated purpose never mentions {cap.name}"
                            ),
                            evidence=make_evidence(
                                f"undeclared-{cap.name}-capability",
                                prop_name,
                                (0, len(prop_name)),
                            ),
                        )
                    )
        return findings
