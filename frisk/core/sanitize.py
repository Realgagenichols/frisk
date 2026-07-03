"""Evidence sanitization: C0-escaping and safe evidence construction (S3, R15).

Everything read back from an untrusted server is escaped before it can reach a terminal or a
report, so embedded ANSI/newlines cannot forge or hide output lines (cross-cutting Pattern 13).
"""

from __future__ import annotations

from frisk.core.models import Evidence

_MAX_SNIPPET = 120


def c0_escape(text: str) -> str:
    """Escape C0 controls, DEL, and C1 controls to ``\\xNN`` form.

    C1 (0x80–0x9f) is included because a raw CSI (0x9b) is as terminal-dangerous as ESC-[.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def char_span_to_byte_span(text: str, char_span: tuple[int, int]) -> tuple[int, int]:
    """Convert a character span (regex coordinates) to a UTF-8 byte span (evidence coordinates).

    Reports promise exact *byte* offsets (R8) so a reviewer can locate hidden content in the
    raw advertised bytes; regex hands us character offsets, so convert explicitly.
    """
    start, end = char_span
    byte_start = len(text[:start].encode("utf-8"))
    byte_end = byte_start + len(text[start:end].encode("utf-8"))
    return (byte_start, byte_end)


def make_evidence(
    category: str,
    text: str,
    char_span: tuple[int, int],
    *,
    redact: bool = False,
) -> Evidence:
    """Build sanitized Evidence for a match on ``text`` at ``char_span``.

    The snippet is C0-escaped and truncated. With ``redact=True`` no matched text is carried
    at all — category, field, and offsets only — for matches whose content is itself sensitive
    (S3: never the raw secret/token/PII value).
    """
    byte_span = char_span_to_byte_span(text, char_span)
    snippet: str | None = None
    if not redact:
        matched = text[char_span[0] : char_span[1]]
        snippet = c0_escape(matched)[:_MAX_SNIPPET]
    return Evidence(category=category, offset=byte_span[0], span=byte_span, snippet=snippet)
