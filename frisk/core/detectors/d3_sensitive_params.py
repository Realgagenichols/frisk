"""D3 — sensitive-parameter capture in inputSchema (R9).

Flags schema properties that quietly solicit data the tool has no business receiving:
conversation history, environment variables, file contents, credentials/tokens, or a
generic unbounded "context"/"metadata" catch-all.

Property NAMES are matched structurally (walking ``properties`` directly), never by running
generic word patterns over all leaves — schema keywords like ``type`` are leaf noise
(tasks/lessons.md). A bounded parameter (enum) named "context" is legitimate (N2).
"""

from __future__ import annotations

import re
from typing import Any

from frisk.core.models import Finding, Inventory, Item, Severity
from frisk.core.sanitize import make_evidence

_I = re.IGNORECASE

# Matched against the full property name.
_NAME_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "conversation-history",
        re.compile(
            r"(?:full_?|entire_?)?conversation(?:_?history)?"
            r"|chat_?(?:history|log)|message_?history|dialog(?:ue)?_?history",
            _I,
        ),
    ),
    ("environment-capture", re.compile(r"^env$|environment|env_?vars?$", _I)),
    ("file-content-capture", re.compile(r"file_?contents?|raw_?file", _I)),
]

# Credential match works on `_`-split name segments so `max_tokens` stays clean but
# `access_token` fires.
_CREDENTIAL_SEGMENTS = {
    "apikey",
    "token",
    "password",
    "passwd",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "auth",
}

# Matched against property descriptions.
_DESC_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "conversation-history",
        re.compile(r"(?:conversation|chat)\s+history|entire\s+conversation", _I),
    ),
    ("environment-capture", re.compile(r"environment\s+variables?", _I)),
    ("file-content-capture", re.compile(r"contents?\s+of\s+[^.\n]{0,40}?file", _I)),
    ("credential-solicitation", re.compile(r"api\s?key|access\s+token|password", _I)),
]

_CATCHALL_NAMES = {"context", "metadata", "meta", "extra", "payload", "data"}


class SensitiveParams:
    id = "D3"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            findings.extend(self._scan_item(item))
        return findings

    def _scan_item(self, item: Item) -> list[Finding]:
        schema = item.input_schema or {}
        props = schema.get("properties")
        if not isinstance(props, dict):
            return []
        findings: list[Finding] = []
        for name, spec in props.items():
            spec = spec if isinstance(spec, dict) else {}
            path = f"inputSchema.properties.{name}"
            findings.extend(self._scan_name(item, path, name))
            description = spec.get("description")
            if isinstance(description, str):
                findings.extend(self._scan_description(item, f"{path}.description", description))
            if self._is_generic_catchall(name, spec):
                findings.append(
                    self._finding(
                        item,
                        f"{path}#key",
                        name,
                        "generic-catchall",
                        f'unbounded catch-all parameter "{name}"',
                    )
                )
        return findings

    def _scan_name(self, item: Item, path: str, name: str) -> list[Finding]:
        findings = []
        for category, pattern in _NAME_RULES:
            if pattern.search(name):
                message = f'property "{name}" solicits {category}'
                findings.append(self._finding(item, f"{path}#key", name, category, message))
        segments = {seg.lower() for seg in name.split("_")}
        if segments & _CREDENTIAL_SEGMENTS or "apikey" in name.lower().replace("_", ""):
            findings.append(
                self._finding(
                    item,
                    f"{path}#key",
                    name,
                    "credential-solicitation",
                    f'property "{name}" solicits a credential or token',
                )
            )
        return findings

    def _scan_description(self, item: Item, path: str, text: str) -> list[Finding]:
        findings = []
        for category, pattern in _DESC_RULES:
            m = pattern.search(text)
            if m:
                findings.append(
                    Finding(
                        detector=self.id,
                        severity=Severity.MEDIUM,
                        item_ref=item.ref,
                        field=path,
                        message=f"parameter description solicits {category}",
                        evidence=make_evidence(category, text, m.span()),
                    )
                )
        return findings

    @staticmethod
    def _is_generic_catchall(name: str, spec: dict[str, Any]) -> bool:
        if name.lower() not in _CATCHALL_NAMES:
            return False
        # Bounded values (enum) or non-text types are narrow, legitimate uses.
        if "enum" in spec or "const" in spec:
            return False
        return spec.get("type") in (None, "string", "object")

    def _finding(
        self, item: Item, field: str, name: str, category: str, message: str
    ) -> Finding:
        return Finding(
            detector=self.id,
            severity=Severity.MEDIUM,
            item_ref=item.ref,
            field=field,
            message=message,
            evidence=make_evidence(category, name, (0, len(name))),
        )
