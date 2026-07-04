"""D1 — instruction injection in tool/resource/prompt prose (R7).

Detects imperative directives aimed at the *model* rather than documentation aimed at the
user: read-this-secret directives, "ignore previous instructions", pseudo-tags like
`<IMPORTANT>`, covert pass-value-as-parameter directives, and secrecy directives.

Each rule requires a suspicious *coupling* (verb + sensitive target, directive + secrecy),
not a lone keyword — plain docs that mention files or parameters must not fire (N2,
cross-cutting Pattern 2).
"""

from __future__ import annotations

import re

from frisk.core.detectors.base import Rule, model_visible_text, scan_item_leaves, scan_text
from frisk.core.models import Finding, Inventory, Severity

_I = re.IGNORECASE

RULES = [
    Rule(
        category="read-sensitive-file",
        severity=Severity.HIGH,
        # "access" is deliberately absent from the verb list: "uses your AWS access
        # credentials" is ordinary docs prose, not a read directive.
        pattern=re.compile(
            r"\b(?:read|open|cat|load|fetch)\b[^.\n]{0,60}?"
            r"(?:~/\.ssh|~/\.aws|id_rsa|id_ed25519|/etc/passwd|\.env\b|private\s+key"
            r"|credentials?\b)",
            _I,
        ),
        message="directive to read a sensitive file or key",
    ),
    Rule(
        category="env-or-secret-exfil",
        severity=Severity.HIGH,
        # Two couplings: broad verbs are only suspicious with an env-var reference
        # ("send $OPENAI_API_KEY"); secret nouns need an exfil-flavored verb — "pass your
        # API key as the api_key parameter" is standard REST docs and must stay clean.
        pattern=re.compile(
            r"\b(?:send|read|include|forward|pass|exfiltrate|copy|upload)\b[^.\n]{0,60}?"
            r"(?:\$[A-Z][A-Z0-9_]{3,}|environment\s+variables?|env\s+vars?)"
            r"|\b(?:exfiltrate|forward|copy|smuggle|steal|harvest)\b[^.\n]{0,60}?"
            r"(?:api[\s_-]?keys?|access\s+tokens?|passwords?|secrets?)",
            _I,
        ),
        message="directive to send environment variables or secrets",
    ),
    Rule(
        category="ignore-previous-instructions",
        severity=Severity.HIGH,
        # "override" is confined to previous/prior instructions|prompts: "override the
        # system default timezone rules" is ordinary prose.
        pattern=re.compile(
            r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|earlier|above|system|all)\b[^.\n]{0,30}?"
            r"\b(?:instructions?|prompts?|rules?|messages?|guidance)"
            r"|\boverride\b[^.\n]{0,40}?\b(?:previous|prior|earlier)\b[^.\n]{0,30}?"
            r"\b(?:instructions?|prompts?)",
            _I,
        ),
        message='"ignore previous instructions" style override',
    ),
    Rule(
        category="pseudo-tag",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"<\s*(?:important|system|instructions?|admin|hidden|secret)\b[^>]*>", _I
        ),
        message="pseudo-tag addressed to the model (e.g. <IMPORTANT>)",
    ),
    Rule(
        category="covert-exfil-param",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:pass|send|forward|include|embed|put)\b[^.\n]{0,80}?"
            r"\b(?:contents?|value|output)\b[^.\n]{0,60}?\bas\b[^.\n]{0,40}?"
            r"\b(?:parameter|param|argument|field)\b",
            _I,
        ),
        message="directive to pass hidden/derived contents as a parameter",
    ),
    Rule(
        category="secrecy-directive",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:do\s+not|don'?t|never)\b[^.\n]{0,40}?"
            r"\b(?:mention|tell|reveal|disclose|report)\b[^.\n]{0,40}?"
            r"\b(?:user|human|anyone)\b",
            _I,
        ),
        message="directive to hide behavior from the user",
    ),
]


class InstructionInjection:
    id = "D1"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            findings.extend(
                scan_item_leaves(self.id, item, RULES, field_filter=model_visible_text)
            )
        # The server-level `instructions` field is injected into the model's context just
        # like tool descriptions — scan it too (R16's "suspicious identity" companion).
        for key in ("instructions", "name"):
            value = inventory.server_info.get(key)
            if isinstance(value, str):
                findings.extend(
                    scan_text(self.id, "(server)", f"serverInfo.{key}", value, RULES)
                )
        return findings
