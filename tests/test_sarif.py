"""SARIF 2.1.0 output (R34).

SARIF is a contract with a consumer that is not in this repo — GitHub code scanning — so
these assert the shape that consumer requires, not merely that JSON came out.
"""

import json

import pytest

from frisk.core.baseline import Baseline, apply_baseline, finding_key
from frisk.core.models import Evidence, Finding, Inventory, Severity
from frisk.core.sarif import SARIF_VERSION, render_sarif
from frisk.core.score import assess

pytestmark = pytest.mark.regression


def finding(
    detector="D1",
    severity=Severity.HIGH,
    category="pseudo-tag",
    snippet=None,
    item="tool:t",
):
    return Finding(
        detector=detector,
        severity=severity,
        item_ref=item,
        field="description",
        message="directive to read a sensitive file or key",
        evidence=Evidence(category=category, offset=12, span=(12, 20), snippet=snippet),
    )


def sarif(findings, **kwargs):
    inventory = Inventory(items=[], server_info={"name": "demo", "version": "1.0"})
    return json.loads(render_sarif(inventory, findings, assess(findings), **kwargs))


def test_document_has_the_envelope_github_requires():
    doc = sarif([finding()])
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "frisk"
    assert driver["informationUri"].startswith("https://")


def test_one_rule_per_detector_with_a_stable_id():
    doc = sarif([finding(detector="D1"), finding(detector="D5"), finding(detector="D1")])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["frisk/D1", "frisk/D5"]
    for rule in rules:
        assert rule["shortDescription"]["text"] and rule["fullDescription"]["text"]
        assert rule["help"]["text"]


def test_every_result_references_a_declared_rule():
    """A result whose ruleId is not in the driver's rule list is rejected by consumers."""
    findings = [finding(detector=d) for d in ("D1", "D3", "D5", "D7")]
    doc = sarif(findings)
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    used = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert used <= declared and used == declared


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.INFO, "note"),
        (Severity.LOW, "warning"),
        (Severity.MEDIUM, "warning"),
        (Severity.HIGH, "error"),
        (Severity.CRITICAL, "error"),
    ],
)
def test_severity_maps_to_a_sarif_level_and_keeps_the_real_one(severity, level):
    doc = sarif([finding(severity=severity)])
    result = doc["runs"][0]["results"][0]
    assert result["level"] == level
    # SARIF's three rungs are coarser than frisk's five, so the true severity must survive.
    assert result["properties"]["severity"] == severity.name


def test_ranks_are_distinct_so_sorting_by_rank_preserves_frisk_ordering():
    ranks = [sarif([finding(severity=s)])["runs"][0]["results"][0]["rank"] for s in Severity]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(list(Severity))


def test_fingerprint_matches_the_baseline_key():
    """A suppression in GitHub's UI and an entry in frisk's baseline must mean the same
    thing, or the two systems disagree about what has been accepted."""
    f = finding()
    doc = sarif([f])
    fingerprint = doc["runs"][0]["results"][0]["partialFingerprints"]["friskFindingKey/v1"]
    assert fingerprint == "|".join(finding_key(f))


def test_no_physical_location_is_invented():
    """frisk findings are about a remote server's advertised definition; there is no file on
    disk. A fabricated path would annotate an unrelated line of the repo."""
    result = sarif([finding()])["runs"][0]["results"][0]
    assert "locations" not in result


def test_baselined_findings_are_suppressed_not_dropped():
    gating, accepted = finding(detector="D1"), finding(detector="D5", category="steering-toward")
    base = Baseline(keys=frozenset({finding_key(accepted)}))
    split = apply_baseline([gating, accepted], base)
    doc = sarif(split.gating, accepted=split.accepted, stale=split.stale, fail_on="high")
    results = doc["runs"][0]["results"]
    assert len(results) == 2, "an accepted finding must still appear, marked"
    suppressed = [r for r in results if "suppressions" in r]
    assert len(suppressed) == 1
    assert suppressed[0]["ruleId"] == "frisk/D5"
    assert suppressed[0]["suppressions"][0]["kind"] == "external"


def test_invocation_carries_the_verdict_and_the_gate():
    doc = sarif([finding()], fail_on="critical", stale=[("D1", "i", "f", "c")])
    props = doc["runs"][0]["invocations"][0]["properties"]
    assert props["verdict"] == "fail"
    assert props["failOn"] == "critical"
    assert props["staleBaselineEntries"] == 1


def test_control_characters_never_reach_the_document_raw():
    """S3/R15: a server-controlled name carrying ANSI must not survive into a file another
    tool will render."""
    hostile = finding(item="tool:\x1b[31mforged\x1b[0m\nsecond line", snippet="\x1b[2K")
    raw = render_sarif(Inventory(items=[]), [hostile], assess([hostile]))
    assert "\x1b" not in raw
    assert "\\u001b" in raw or "\\\\x1b" in raw
    doc = json.loads(raw)
    assert "\x1b" not in json.dumps(doc)


def test_empty_scan_is_still_a_valid_document():
    doc = sarif([])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
