"""Risk score / verdict / exit-code tests (R13, R18)."""

from frisk.core.models import Evidence, Finding, Severity
from frisk.core.score import MAX_SCORE, Assessment, assess, exit_code


def finding(severity: Severity) -> Finding:
    return Finding(
        detector="DX",
        severity=severity,
        item_ref="tool:t",
        field="description",
        message="m",
        evidence=Evidence(category="c"),
    )


def test_no_findings_is_clean_pass():
    a = assess([])
    assert (a.score, a.verdict, a.highest) == (0, "pass", None)
    assert exit_code(a) == 0


def test_info_only_still_passes():
    a = assess([finding(Severity.INFO)] * 5)
    assert a.verdict == "pass" and a.score == 0
    assert exit_code(a) == 0


def test_low_and_medium_warn_exit_1():
    for sev in (Severity.LOW, Severity.MEDIUM):
        a = assess([finding(sev)])
        assert a.verdict == "warn" and a.highest is sev
        assert exit_code(a) == 1


def test_high_and_critical_fail_exit_2():
    for sev in (Severity.HIGH, Severity.CRITICAL):
        a = assess([finding(sev)])
        assert a.verdict == "fail" and a.highest is sev
        assert exit_code(a) == 2


def test_highest_severity_drives_verdict_not_count():
    # 10 LOWs never outrank 1 HIGH in verdict terms.
    a = assess([finding(Severity.LOW)] * 10 + [finding(Severity.HIGH)])
    assert a.verdict == "fail" and a.highest is Severity.HIGH


def test_score_is_weighted_and_capped():
    one_medium = assess([finding(Severity.MEDIUM)])
    one_high = assess([finding(Severity.HIGH)])
    assert 0 < one_medium.score < one_high.score
    flooded = assess([finding(Severity.CRITICAL)] * 50)
    assert flooded.score == MAX_SCORE


def test_assessment_is_deterministic():
    fs = [finding(Severity.MEDIUM), finding(Severity.HIGH)]
    assert assess(fs) == assess(list(reversed(fs))) == Assessment(20, "fail", Severity.HIGH)
