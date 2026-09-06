"""Baseline and severity-threshold tests (R32, R33).

The baseline is the one feature here that can make frisk report a server as clean when it is
not. Most of these tests are therefore about what it must REFUSE to suppress.
"""

import json

import pytest

from frisk.core.baseline import (
    BASELINE_VERSION,
    Baseline,
    BaselineError,
    apply_baseline,
    finding_key,
    load_baseline,
    render_baseline,
)
from frisk.core.models import Evidence, Finding, Severity
from frisk.core.score import assess, exit_code, parse_fail_on

pytestmark = pytest.mark.regression


def finding(
    detector="D5",
    severity=Severity.MEDIUM,
    item="tool:read_file",
    field_path="name",
    category="common-name-impersonation",
    offset=0,
    message="m",
):
    return Finding(
        detector=detector,
        severity=severity,
        item_ref=item,
        field=field_path,
        message=message,
        evidence=Evidence(category=category, offset=offset, span=(offset, offset + 4)),
    )


# ── the key: what must and must not change a finding's identity ─────────────


def test_key_ignores_offset_span_and_message():
    """A reworded description moves every offset. An offset-keyed baseline would go stale on
    cosmetic edits, which teaches people to regenerate it blindly — and that is how a real
    finding gets accepted by accident."""
    a = finding(offset=10, message="wording one")
    b = finding(offset=873, message="wording two, after a detector improvement")
    assert finding_key(a) == finding_key(b)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("detector", "D1"),
        ("item", "tool:other"),
        ("field_path", "description"),
        ("category", "steering-toward"),
    ],
)
def test_key_distinguishes_every_identifying_part(field, value):
    # P105: assert each part discriminates, not merely that some do.
    assert finding_key(finding()) != finding_key(finding(**{field: value}))


# ── applying a baseline ─────────────────────────────────────────────────────


def test_accepted_findings_do_not_gate_but_are_still_returned():
    findings = [finding(), finding(detector="D1", severity=Severity.HIGH, category="pseudo-tag")]
    base = Baseline(keys=frozenset({finding_key(findings[0])}))
    result = apply_baseline(findings, base)
    assert result.accepted == [findings[0]]
    assert result.gating == [findings[1]]
    assert result.stale == []


def test_a_new_category_on_a_baselined_item_is_not_suppressed():
    """The whole reason the key includes the category. Accepting "this tool is noisy" would
    suppress a LATER, different finding on it — exactly the rug-pull frisk exists to catch."""
    accepted = finding()
    base = Baseline(keys=frozenset({finding_key(accepted)}))
    poisoned = finding(detector="D1", severity=Severity.HIGH, category="read-sensitive-file")
    result = apply_baseline([accepted, poisoned], base)
    assert result.gating == [poisoned]
    assert exit_code(assess(result.gating)) == 2


def test_repeated_findings_sharing_a_key_are_all_accepted():
    # Two hits of the same rule on the same field at different offsets share one key, and one
    # baseline entry accepts both — which is the point of an offset-free key.
    findings = [finding(offset=0), finding(offset=99)]
    base = Baseline(keys=frozenset({finding_key(findings[0])}))
    result = apply_baseline(findings, base)
    assert len(result.accepted) == 2 and result.gating == []


def test_stale_entries_are_reported():
    """An accepted finding that has since been FIXED must stop being accepted silently, or the
    baseline grows into a list of permissions nobody has re-read (Pattern 27)."""
    gone = finding(item="tool:deleted")
    base = Baseline(keys=frozenset({finding_key(finding()), finding_key(gone)}))
    result = apply_baseline([finding()], base)
    assert result.stale == [finding_key(gone)]


def test_empty_baseline_changes_nothing():
    findings = [finding(), finding(detector="D1")]
    result = apply_baseline(findings, Baseline(keys=frozenset()))
    assert result.gating == findings and result.accepted == []


# ── the file format ─────────────────────────────────────────────────────────


def test_round_trip_preserves_exactly_the_keys():
    findings = [finding(), finding(detector="D1", category="pseudo-tag"), finding(offset=50)]
    loaded = load_baseline(render_baseline(findings))
    assert loaded.keys == {finding_key(f) for f in findings}


def test_rendered_baseline_is_deterministic_and_sorted():
    """It is meant to be committed. A file that reorders itself on every write is
    unreviewable in a diff, and an unreviewable diff gets rubber-stamped."""
    findings = [finding(detector="D7"), finding(detector="D1"), finding(detector="D4")]
    once = render_baseline(findings)
    assert once == render_baseline(list(reversed(findings)))
    detectors = [e["detector"] for e in json.loads(once)["findings"]]
    assert detectors == sorted(detectors)


def test_rendered_baseline_carries_no_timestamp():
    # Churn in a header trains reviewers to skim past the part that matters; git already
    # records when the file changed.
    doc = json.loads(render_baseline([finding()]))
    assert set(doc) == {"version", "note", "findings"}
    assert doc["version"] == BASELINE_VERSION


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{not json", "not valid JSON"),
        ("[]", "must be a JSON object"),
        ('{"version": 99, "findings": []}', "unsupported baseline version"),
        ('{"version": 1}', "missing a 'findings' array"),
        ('{"version": 1, "findings": [1]}', "must be an object"),
        ('{"version": 1, "findings": [{"detector": "D1"}]}', "missing 'item'"),
        (
            '{"version": 1, "findings": [{"detector":"D1","item":"i","field":"f","category":2}]}',
            "must all be strings",
        ),
    ],
)
def test_malformed_baselines_fail_loudly_and_specifically(text, expected):
    """A baseline that silently parsed as empty would turn the gate off without saying so —
    the worst outcome available here (R6)."""
    with pytest.raises(BaselineError) as excinfo:
        load_baseline(text)
    assert expected in str(excinfo.value)


# ── the severity threshold (R32) ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("severities", "default", "at_medium", "at_critical"),
    [
        ([], 0, 0, 0),
        ([Severity.INFO], 0, 0, 0),
        ([Severity.LOW], 1, 1, 1),
        ([Severity.MEDIUM], 1, 2, 1),
        ([Severity.HIGH], 2, 2, 1),
        ([Severity.CRITICAL], 2, 2, 2),
        # Accumulated MEDIUMs promote to a HIGH-equivalent (R13), so they fail by default —
        # but someone who asked only to be woken for CRITICALs still is not.
        ([Severity.MEDIUM] * 12, 2, 2, 1),
    ],
)
def test_fail_on_moves_only_the_line_between_1_and_2(
    severities, default, at_medium, at_critical
):
    assessment = assess([finding(severity=s) for s in severities])
    assert exit_code(assessment) == default
    assert exit_code(assessment, parse_fail_on("medium")) == at_medium
    assert exit_code(assessment, parse_fail_on("critical")) == at_critical


def test_fail_on_low_binds_at_its_own_edge():
    # P101: a threshold only proves itself where it binds.
    low = assess([finding(severity=Severity.LOW)])
    assert exit_code(low, parse_fail_on("low")) == 2
    assert exit_code(low, parse_fail_on("medium")) == 1


def test_default_threshold_is_the_original_contract():
    assert parse_fail_on("high") is Severity.HIGH
    for severity in Severity:
        assessment = assess([finding(severity=severity)])
        assert exit_code(assessment) == {"pass": 0, "warn": 1, "fail": 2}[assessment.verdict]


def test_parse_fail_on_rejects_nonsense():
    with pytest.raises(ValueError, match="unknown severity"):
        parse_fail_on("catastrophic")
