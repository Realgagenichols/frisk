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

from frisk.core.detectors.base import iter_schema_properties
from frisk.core.models import Finding, Inventory, Item, Severity
from frisk.core.sanitize import make_evidence

_I = re.IGNORECASE

# Full-matched against the property name (after camelCase→snake normalization): anchored so
# `conversation_id` — ubiquitous on legitimate chat tools — never matches (Pattern 2).
_NAME_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "conversation-history",
        # Still `fullmatch`ed, which is what keeps `conversation_id` clean (Pattern 2).
        # Stems split into two tiers: `conversation`/`transcript` are specific enough alone,
        # while `messages`, `history`, `memory` and `chat` are ordinary parameter names on
        # honest tools and only count when a scope qualifier makes them total
        # (`all_messages`, `full_history`). W3b fixed exactly that false positive once — do
        # not re-widen it.
        re.compile(
            r"(?:full|entire|all|prior|previous|complete)_?"
            r"(?:conversation|chat|dialog(?:ue)?|message|transcript|history|memory|context)s?"
            r"(?:_?(?:history|log))?"
            r"|(?:conversation|transcript)s?(?:_?(?:history|log))?"
            r"|(?:chat|message|dialog(?:ue)?)_?(?:history|log)"
            r"|context_?window|system_?prompt",
            _I,
        ),
    ),
    ("environment-capture", re.compile(r"env|environment(?:_?var(?:iable)?s?)?|env_?vars?", _I)),
    ("file-content-capture", re.compile(r".*(?:file_?contents?|raw_?file).*", _I)),
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
    "cookie",
    "cookies",
    "bearer",
    "keyfile",
    "keypair",
    "passphrase",
    "pat",
}

# Bare "key" cannot go in the segment set — `sort_key`, `cache_key`, `primary_key`, `api_key`
# already covered — so the key-shaped names are matched as a QUALIFIER + key pair instead.
_KEY_QUALIFIERS = {"private", "ssh", "signing", "secret", "session", "encryption", "identity"}
_KEY_NOUNS = {"key", "keys", "file"}  # `identity_file`/`secret_file` are key paths by another name

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


def _snake(name: str) -> str:
    """Normalize camelCase to snake_case so `accessToken` matches like `access_token`."""
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)


class SensitiveParams:
    id = "D3"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            findings.extend(self._scan_item(item))
        return findings

    def _scan_item(self, item: Item) -> list[Finding]:
        findings: list[Finding] = []
        for path, name, spec in iter_schema_properties(item.input_schema or {}):
            # Enum/const-bounded values can't capture free-form sensitive data — the same
            # bounding logic the catch-all rule applies (Pattern 3).
            if "enum" not in spec and "const" not in spec:
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
        normalized = _snake(name)
        for category, pattern in _NAME_RULES:
            if pattern.fullmatch(normalized):
                message = f'property "{name}" solicits {category}'
                findings.append(self._finding(item, f"{path}#key", name, category, message))
        segments = {seg.lower() for seg in normalized.split("_")}
        qualified_key = bool(segments & _KEY_NOUNS) and bool(segments & _KEY_QUALIFIERS)
        if (
            segments & _CREDENTIAL_SEGMENTS
            or qualified_key
            or "apikey" in name.lower().replace("_", "")
        ):
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
        # Bounded values (enum/const) or non-text types are narrow, legitimate uses; so is
        # an object with declared sub-properties — a structured body, not a catch-all.
        if "enum" in spec or "const" in spec:
            return False
        if spec.get("type") == "object" and spec.get("properties"):
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
