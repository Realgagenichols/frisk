"""Reporter tests: human/JSON rendering, injection-safety, secret hygiene (R15, R17, S3)."""

import json

from frisk.core.models import Evidence, Finding, Inventory, ItemKind, Severity
from frisk.core.report import render_human, render_json
from frisk.core.sanitize import make_evidence
from frisk.core.score import assess
from tests.fixtures.definitions import D1_POISONED, as_item

SENTINEL = "sk-SENTINEL-9x7"


def make_finding(**kw) -> Finding:
    defaults = dict(
        detector="D1",
        severity=Severity.HIGH,
        item_ref="tool:t",
        field="description",
        message="a directive",
        evidence=Evidence(category="cat", offset=3, span=(3, 9), snippet="matched"),
    )
    defaults.update(kw)
    return Finding(**defaults)


def make_inventory() -> Inventory:
    return Inventory(items=[as_item(D1_POISONED)], server_info={"name": "srv", "version": "1"})


def test_human_report_contains_verdict_score_and_finding():
    findings = [make_finding()]
    out = render_human(make_inventory(), findings, assess(findings))
    assert "verdict: FAIL" in out
    assert "risk score:" in out
    assert "[HIGH] D1 instruction-injection" in out
    assert "@ byte 3" in out


def test_human_report_clean_run():
    out = render_human(make_inventory(), [], assess([]))
    assert "verdict: PASS" in out and "no findings" in out


def test_malicious_item_name_cannot_forge_report_lines():
    # A tool name carrying a newline + fake report line and ANSI clear-screen (R15).
    evil_ref = "tool:evil\n[CRITICAL] D9 forged — you-are-clean"
    findings = [make_finding(item_ref=evil_ref, message="msg\x1b[2Jwiped")]
    out = render_human(make_inventory(), findings, assess(findings))
    assert "\x1b" not in out  # no raw ESC anywhere
    # the embedded newline is escaped, so no rendered line STARTS with the forged text
    assert not any(line.startswith("[CRITICAL] D9 forged") for line in out.split("\n"))
    assert "\\x0a" in out  # the newline is visibly escaped


def test_json_report_schema_stable_and_parseable():
    findings = [make_finding()]
    doc = json.loads(render_json(make_inventory(), findings, assess(findings)))
    assert set(doc) == {
        "frisk_version",
        "verdict",
        "risk_score",
        "highest_severity",
        "items_scanned",
        "server_info",
        "findings",
    }
    f = doc["findings"][0]
    assert set(f) == {"detector", "severity", "item", "field", "message", "evidence"}
    assert set(f["evidence"]) == {"category", "offset", "span", "snippet"}
    assert f["severity"] == "HIGH" and doc["verdict"] == "fail"


def test_json_report_has_no_raw_control_characters():
    findings = [make_finding(message="m\x1b[31m\nx")]
    raw = render_json(make_inventory(), findings, assess(findings))
    # serialized JSON must never carry a raw control char (ensure_ascii)
    assert not any(ord(c) < 0x20 for c in raw.replace("\n", "").replace(" ", ""))


def test_redacted_secret_value_never_appears_in_either_format():
    # S3: evidence built with redact=True carries offsets only — render both formats.
    text = f"header {SENTINEL} trailer"
    ev = make_evidence("credential-solicitation", text, (7, 7 + len(SENTINEL)), redact=True)
    findings = [make_finding(evidence=ev)]
    inv = make_inventory()
    human = render_human(inv, findings, assess(findings))
    machine = render_json(inv, findings, assess(findings))
    assert SENTINEL not in human and SENTINEL not in machine
    assert "@ byte 7" in human  # location stays actionable


def test_findings_ordered_most_severe_first():
    findings = [
        make_finding(severity=Severity.LOW, detector="D7"),
        make_finding(severity=Severity.CRITICAL, detector="D2"),
        make_finding(severity=Severity.MEDIUM, detector="D3"),
    ]
    out = render_human(make_inventory(), findings, assess(findings))
    positions = [out.index(f"[{s}]") for s in ("CRITICAL", "MEDIUM", "LOW")]
    assert positions == sorted(positions)


def test_item_kind_counts_in_header():
    items = [as_item(D1_POISONED), as_item(D1_POISONED, kind=ItemKind.PROMPT)]
    inv = Inventory(items=items, server_info={"name": "s"})
    out = render_human(inv, [], assess([]))
    assert "1 tools" in out and "0 resources" in out and "1 prompts" in out
