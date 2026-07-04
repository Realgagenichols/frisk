"""D2 — hidden / invisible content in any item field (R8).

Flags content a human reviewer cannot see but the model (or a terminal) will act on:
zero-width characters, Unicode tag characters (decoded back to the ASCII they smuggle),
bidi/RTL overrides, ANSI escape sequences, HTML comments, unusual line separators, and
mixed-script homoglyph words. Evidence carries exact UTF-8 byte offsets (R8), computed from
the raw character positions — this detector scans every leaf, keys included, because a
hidden character is suspicious anywhere (cross-cutting Pattern 13).
"""

from __future__ import annotations

import re
import unicodedata

from frisk.core.models import Evidence, Finding, Inventory, Severity, iter_string_leaves
from frisk.core.sanitize import c0_escape, char_span_to_byte_span

_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]+")
_TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]+")
_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]+")
_ANSI = re.compile(r"\x1b\[[0-9;:?]*[ -/]*[@-~]|\x9b[0-9;:?]*[ -/]*[@-~]|\x1b|\x9b")
_LINE_SEP = re.compile(r"[\u2028\u2029\u0085]+")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)

_LETTER_SCRIPTS_OF_CONCERN = ("CYRILLIC", "GREEK")

# Single non-Latin letters common in legitimate technical prose (μs, Ω, π) — a word whose
# only non-Latin characters are these is unit notation, not a homoglyph attack.
_TECH_LETTER_ALLOWLIST = {"μ", "Ω", "π"}  # μ Ω π


def _is_pictographic(ch: str) -> bool:
    cp = ord(ch)
    return (
        cp >= 0x1F000
        or 0x2600 <= cp <= 0x27BF
        or cp == 0xFE0F  # variation selector-16 in emoji sequences
        or unicodedata.category(ch) == "So"
    )


def _codepoint_list(text: str) -> str:
    return " ".join(f"U+{ord(ch):04X}" for ch in text[:8]) + ("…" if len(text) > 8 else "")


def _decode_tags(text: str) -> str:
    # Tag characters map ASCII 0x20–0x7E into invisible U+E0020–U+E007E.
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)


class HiddenContent:
    id = "D2"

    def run(self, inventory: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for item in inventory.items:
            for field_path, text in iter_string_leaves(item):
                findings.extend(self._scan(item.ref, field_path, text))
        # Server identity metadata is rendered to humans and injected into model context —
        # hidden characters there are as dangerous as in any item field (R16 companion).
        for key, value in inventory.server_info.items():
            if isinstance(value, str):
                findings.extend(self._scan("(server)", f"serverInfo.{key}", value))
        return findings

    @staticmethod
    def _is_emoji_joiner(text: str, m: re.Match[str]) -> bool:
        if set(m.group()) != {"\u200d"}:
            return False
        start, end = m.span()
        return (
            start > 0
            and end < len(text)
            and _is_pictographic(text[start - 1])
            and _is_pictographic(text[end])
        )

    def _scan(self, item_ref: str, field_path: str, text: str) -> list[Finding]:
        out: list[Finding] = []

        def add(category, severity, span, snippet, message):
            byte_span = char_span_to_byte_span(text, span)
            out.append(
                Finding(
                    detector=self.id,
                    severity=severity,
                    item_ref=item_ref,
                    field=field_path,
                    message=message,
                    evidence=Evidence(
                        category=category,
                        offset=byte_span[0],
                        span=byte_span,
                        snippet=snippet,
                    ),
                )
            )

        for m in _ZERO_WIDTH.finditer(text):
            if self._is_emoji_joiner(text, m):
                continue  # ZWJ inside an emoji sequence (👨\u200d👩\u200d👧) is benign
            add(
                "zero-width",
                Severity.HIGH,
                m.span(),
                _codepoint_list(m.group()),
                "zero-width character(s) — invisible to a human reviewer",
            )
        for m in _TAG_CHARS.finditer(text):
            decoded = _decode_tags(m.group())
            add(
                "unicode-tag",
                Severity.HIGH,
                m.span(),
                f"decodes to: {c0_escape(decoded)[:100]}",
                "Unicode tag characters smuggling hidden text",
            )
        for m in _BIDI.finditer(text):
            add(
                "bidi-override",
                Severity.HIGH,
                m.span(),
                _codepoint_list(m.group()),
                "bidi/RTL override — rendered text differs from raw text",
            )
        for m in _ANSI.finditer(text):
            add(
                "ansi-escape",
                Severity.HIGH,
                m.span(),
                c0_escape(m.group()),
                "ANSI escape sequence — can rewrite or hide terminal output",
            )
        for m in _LINE_SEP.finditer(text):
            add(
                "unicode-linebreak",
                Severity.MEDIUM,
                m.span(),
                _codepoint_list(m.group()),
                "non-standard Unicode line separator",
            )
        for m in _HTML_COMMENT.finditer(text):
            add(
                "html-comment",
                Severity.MEDIUM,
                m.span(),
                c0_escape(m.group())[:100],
                "HTML comment — hidden in rendered views",
            )
        for m in _WORD.finditer(text):
            scripts = {self._script(ch) for ch in m.group()}
            non_latin = {ch for ch in m.group() if self._script(ch) != "LATIN"}
            if non_latin <= _TECH_LETTER_ALLOWLIST:
                continue  # unit notation like "μs" (Pattern 2)
            if "LATIN" in scripts and scripts & set(_LETTER_SCRIPTS_OF_CONCERN):
                add(
                    "mixed-script-homoglyph",
                    Severity.MEDIUM,
                    m.span(),
                    c0_escape(m.group())[:40],
                    "mixed-script word — possible homoglyph impersonation",
                )
        return out

    @staticmethod
    def _script(ch: str) -> str:
        try:
            return unicodedata.name(ch).split(" ")[0]
        except ValueError:
            return "UNKNOWN"
