"""Tests for the detector framework: error-to-finding, overlap suppression, sanitization.

Covers R12, S3, and cross-cutting Patterns 1, 6, 11, 13.
"""

from dataclasses import dataclass

from frisk.core.engine import run_detectors, suppress_overlaps
from frisk.core.models import Evidence, Finding, Inventory, Severity
from frisk.core.sanitize import c0_escape, char_span_to_byte_span, make_evidence

SENTINEL_SECRET = "sk-SENTINEL-abc123"


@dataclass
class FakeDetector:
    id: str
    result: list[Finding] | Exception

    def run(self, inventory: Inventory) -> list[Finding]:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def finding(
    detector="DX",
    severity=Severity.MEDIUM,
    item_ref="tool:t",
    field="description",
    span=(0, 5),
    category="test",
) -> Finding:
    return Finding(
        detector=detector,
        severity=severity,
        item_ref=item_ref,
        field=field,
        message="m",
        evidence=Evidence(category=category, offset=span[0] if span else None, span=span),
    )


# --- error-to-finding (R12, Pattern 6) ---------------------------------------------------


def test_raising_detector_emits_finding_not_silent_pass():
    boom = FakeDetector("D9", ValueError(f"bad input: {SENTINEL_SECRET}"))
    findings = run_detectors(Inventory(), [boom])
    assert len(findings) == 1
    f = findings[0]
    assert f.detector == "D9"
    assert f.severity is Severity.HIGH
    assert "errored" in f.message and "ValueError" in f.message


def test_error_finding_never_echoes_exception_contents():
    # Pattern 11: exception reprs can quote untrusted input — only the type name may appear.
    boom = FakeDetector("D9", ValueError(f"bad input: {SENTINEL_SECRET}"))
    findings = run_detectors(Inventory(), [boom])
    assert SENTINEL_SECRET not in repr(findings)


def test_error_in_one_detector_does_not_stop_others():
    ok = FakeDetector("D1", [finding(detector="D1")])
    boom = FakeDetector("D2", RuntimeError("x"))
    findings = run_detectors(Inventory(), [ok, boom])
    detectors = {f.detector for f in findings}
    assert detectors == {"D1", "D2"}


# --- overlap suppression (R12, Pattern 1) ------------------------------------------------


def test_specific_match_suppresses_overlapping_generic():
    specific = finding(detector="D1", severity=Severity.HIGH, span=(0, 40))
    generic = finding(detector="D5", severity=Severity.MEDIUM, span=(10, 18))
    kept = suppress_overlaps([generic, specific])
    assert kept == [specific]


def test_higher_severity_never_hidden_by_longer_lower_severity():
    long_medium = finding(detector="D4", severity=Severity.MEDIUM, span=(0, 50))
    short_high = finding(detector="D2", severity=Severity.HIGH, span=(5, 9))
    kept = suppress_overlaps([long_medium, short_high])
    assert kept == [short_high]


def test_non_overlapping_matches_both_kept():
    a = finding(detector="D1", span=(0, 5))
    b = finding(detector="D2", span=(10, 15))
    assert len(suppress_overlaps([a, b])) == 2


def test_same_span_different_fields_both_kept():
    a = finding(detector="D1", field="description", span=(0, 5))
    b = finding(detector="D1", field="name", span=(0, 5))
    assert len(suppress_overlaps([a, b])) == 2


def test_same_span_different_items_both_kept():
    a = finding(item_ref="tool:a", span=(0, 5))
    b = finding(item_ref="tool:b", span=(0, 5))
    assert len(suppress_overlaps([a, b])) == 2


def test_spanless_findings_never_suppressed():
    spanless = finding(detector="D7", span=None)
    wide = finding(detector="D1", severity=Severity.HIGH, span=(0, 100))
    assert len(suppress_overlaps([spanless, wide])) == 2


def test_suppression_is_deterministic_regardless_of_input_order():
    fs = [
        finding(detector="D1", severity=Severity.HIGH, span=(0, 40)),
        finding(detector="D5", severity=Severity.MEDIUM, span=(10, 18)),
        finding(detector="D2", severity=Severity.MEDIUM, span=(50, 60)),
    ]
    assert suppress_overlaps(fs) == suppress_overlaps(list(reversed(fs)))


# --- sanitization (S3, R15, Pattern 13) --------------------------------------------------


def test_c0_escape_neutralizes_ansi_and_newlines():
    escaped = c0_escape("a\x1b[31mred\nline\x00\x9bcsi")
    assert "\x1b" not in escaped and "\n" not in escaped and "\x9b" not in escaped
    assert "\\x1b" in escaped and "\\x0a" in escaped and "\\x9b" in escaped


def test_c0_escape_leaves_printable_text_alone():
    assert c0_escape("hello wörld") == "hello wörld"


def test_char_span_to_byte_span_multibyte():
    #        char:  0   1   2 3 4
    text = "é" * 2 + "abc"  # 'é' is 2 bytes in UTF-8
    assert char_span_to_byte_span(text, (2, 5)) == (4, 7)


def test_make_evidence_escapes_snippet_and_converts_offsets():
    text = "x\x1b[2Jhidden"
    ev = make_evidence("ansi-escape", text, (1, 5))
    assert ev.offset == 1
    assert ev.snippet is not None and "\x1b" not in ev.snippet


def test_make_evidence_redact_drops_matched_text_entirely():
    text = f"token={SENTINEL_SECRET} trailing"
    ev = make_evidence("credential-solicitation", text, (6, 6 + len(SENTINEL_SECRET)), redact=True)
    assert ev.snippet is None
    assert SENTINEL_SECRET not in repr(ev)
    assert ev.offset == 6  # location info remains actionable
