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
    prints = sarif([f])["runs"][0]["results"][0]["partialFingerprints"]
    assert prints["friskFindingKey/v2"] == "|".join(finding_key(f))


def test_every_result_carries_a_location():
    """GitHub REJECTS the whole upload for a result with no locations —
    `locationFromSarifResult: expected at least one location` — and its docs state at least
    one is required. An earlier version omitted them on the reasoning that there is no file
    to point at, which was true and produced a document the one consumer R34 names would not
    accept. This test exists so that cannot recur."""
    for result in sarif([finding(), finding(detector="D5")])["runs"][0]["results"]:
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"]
        assert physical["region"]["startLine"] >= 1


def test_the_anchor_is_a_real_workspace_path_not_a_fabricated_one():
    """The location must be somewhere that actually exists in the checkout, or GitHub cannot
    resolve it. Single-target mode anchors on the lockfile frisk writes."""
    doc = json.loads(
        render_sarif(
            Inventory(items=[]),
            [finding()],
            assess([finding()]),
            location_path="custom/frisk.lock",
        )
    )
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert uri["artifactLocation"]["uri"] == "custom/frisk.lock"


def test_github_readable_fingerprint_is_supplied_and_stable():
    """GitHub reads only `primaryLocationLineHash`, and cannot compute one itself without
    source text at the location — so frisk must supply it, derived from LOGICAL identity so
    an unrelated edit to the anchor file does not churn every alert."""
    prints = sarif([finding()])["runs"][0]["results"][0]["partialFingerprints"]
    assert "primaryLocationLineHash" in prints
    # Same finding, different anchor line/file -> same fingerprint.
    other = json.loads(
        render_sarif(
            Inventory(items=[]),
            [finding()],
            assess([finding()]),
            location_path="somewhere/else.lock",
        )
    )["runs"][0]["results"][0]["partialFingerprints"]
    assert other["primaryLocationLineHash"] == prints["primaryLocationLineHash"]


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


# ── a whole config as ONE run (R36, shape A) ───────────────────────────────


def scan_of(name, findings=(), status="scanned", line=1, error=None):
    from frisk.core.multi import ServerScan

    fs = list(findings)
    return ServerScan(
        name=name,
        status=status,
        inventory=Inventory(items=[], server_info={"name": name}),
        assessment=assess(fs),
        gating=fs,
        error=error,
        config_line=line,
    )


def multi(scans, config="mcp.json"):
    from frisk.core.sarif import render_multi_sarif

    return json.loads(render_multi_sarif(scans, config, fail_on="high"))


def test_a_config_is_one_run_not_one_run_per_server():
    """A SARIF run is an alert-lifecycle slot. One run per server would make each server its
    own code-scanning configuration, so REMOVING a bad server — the actual remediation —
    would orphan its alerts open forever instead of closing them. GitHub also rejects runs
    that share a tool and category, and caps runs at 20."""
    doc = multi([scan_of("a", [finding()]), scan_of("b", [finding(detector="D5")])])
    assert len(doc["runs"]) == 1
    assert len(doc["runs"][0]["results"]) == 2


def test_results_are_anchored_at_the_line_declaring_their_server():
    doc = multi([scan_of("a", [finding()], line=7), scan_of("b", [finding()], line=12)])
    results = doc["runs"][0]["results"]
    lines = {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results}
    assert lines == {7, 12}
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert uris == {"mcp.json"}


def test_the_same_finding_under_two_servers_stays_two_alerts():
    """Two installations of the same poisoned tool are two separate trust decisions, each
    fixed by uninstalling a different server. Identical fingerprints would merge them into
    one alert and one of the two would silently disappear."""
    doc = multi([scan_of("alpha", [finding()]), scan_of("beta", [finding()])])
    prints = [r["partialFingerprints"] for r in doc["runs"][0]["results"]]
    assert len({p["primaryLocationLineHash"] for p in prints}) == 2
    assert len({p["friskFindingKey/v2"] for p in prints}) == 2


def test_a_server_that_failed_to_enumerate_becomes_a_result():
    """The auto-close behaviour that makes one merged run correct would otherwise turn a
    failed server's previous alerts green — it contributes no findings, so it looks exactly
    like a clean scan. An unassessed server is not a clean one (R6)."""
    doc = multi([scan_of("ok", [finding()]), scan_of("dead", status="error", error="boom")])
    errors = [r for r in doc["runs"][0]["results"] if r["ruleId"] == "frisk/scan-error"]
    assert len(errors) == 1
    assert errors[0]["level"] == "error"
    assert "not a clean one" in errors[0]["message"]["text"]
    assert "locations" in errors[0]
    declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "frisk/scan-error" in declared


def test_the_scan_error_rule_is_absent_when_nothing_failed():
    doc = multi([scan_of("ok", [finding()])])
    assert "frisk/scan-error" not in {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}


def test_a_failed_server_makes_the_whole_config_fail():
    doc = multi([scan_of("ok"), scan_of("dead", status="error", error="boom")])
    assert doc["runs"][0]["invocations"][0]["properties"]["verdict"] == "fail"
    assert doc["runs"][0]["invocations"][0]["properties"]["serversFailed"] == 1
