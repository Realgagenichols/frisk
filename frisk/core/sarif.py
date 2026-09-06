"""SARIF 2.1.0 output (R34) — the format GitHub code scanning ingests.

Uploading SARIF is how a scanner stops being a log line and starts being an annotation on
the pull request that introduced the problem. The mapping is deliberately conservative:

- one SARIF **rule** per detector, with a stable id (`frisk/D1`), so GitHub can track a
  finding across runs and a suppression in its UI keeps meaning the same thing;
- one **result** per finding;
- **a real physical location, always.** SARIF permits a result with no `locations`, and the
  Microsoft validator accepts one — but GitHub's ingestion rejects the whole upload with
  `locationFromSarifResult: expected at least one location`, and its docs state "At least one
  location is required for code scanning to display a result". An earlier version of this
  module omitted locations on the reasoning that frisk's findings describe a *remote* server
  and there is no file to point at. That reasoning was sound and the output was unusable:
  it was never checked against the consumer the requirement names.

  There is an honest anchor in both modes. Under `--config` it is the config file and the
  line declaring that server — the finding genuinely IS "this entry pulls in a poisoned
  tool", and removing that line is the fix. For a single target it is the lockfile path,
  which frisk writes into the workspace and which stands for that server.

- **a self-computed `primaryLocationLineHash`.** GitHub reads only that key out of
  `partialFingerprints`, and it can only compute one itself from source text at a location —
  which for us would hash the config LINE, so reordering the file would close and reopen
  every alert. Ours hashes the logical identity instead, so an alert survives an unrelated
  edit and dies only when the finding does.

Verified against a live repository on 2026-09-06, not just against the docs: a 23-result
document across three servers uploaded with `processing_status: complete`, `errors: null`,
and produced 23 distinct alerts anchored at the right config lines. Re-uploading the same
document produced no duplicates, and removing a server closed its 21 alerts as `fixed` —
which is the auto-close property the single-run shape exists to get.

Pure core, no I/O, no secret values (S3) — evidence carries categories and offsets, and the
snippet is already C0-escaped and credential-masked by `sanitize.make_evidence`.
"""

from __future__ import annotations

import hashlib
import json

from frisk import __version__
from frisk.core.baseline import finding_key
from frisk.core.models import Finding, Inventory, Severity
from frisk.core.report import DETECTOR_LABELS
from frisk.core.sanitize import c0_escape
from frisk.core.score import Assessment

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF has three failure levels plus "none". MEDIUM and LOW both land on `warning`, which is
# GitHub's only middle rung; the true severity travels in `rank` and in the properties so
# nothing is lost.
_LEVELS: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "warning",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# 0.0–1.0, so a consumer sorting by rank gets frisk's ordering rather than SARIF's coarser one.
_RANKS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 100.0,
}

_RULE_HELP: dict[str, str] = {
    "D1": "Instructions aimed at the model rather than the user: directives to read secrets, "
    "'ignore previous instructions', pseudo-tags, or covert exfiltration as a parameter.",
    "D2": "Content a human reviewer cannot see but the model reads: zero-width and "
    "default-ignorable characters, Unicode tag characters, bidi overrides, ANSI escapes, "
    "HTML comments, homoglyphs.",
    "D3": "Schema properties soliciting data the tool has no business receiving: conversation "
    "history, environment variables, file contents, credentials, or an unbounded catch-all.",
    "D4": "A tool requesting a shell, file or network capability its stated purpose never "
    "declares — or advertising an exec/file primitive at all.",
    "D5": "A name impersonating a common built-in tool, two definitions sharing one name, or "
    "prose steering the model toward this tool and away from others.",
    "D6": "A definition changed since the frisk.lock baseline was taken (rug-pull).",
    "D7": "Metadata hygiene: code sourced from a remote or unpinned location, missing or "
    "unpinned server identity.",
    "D8": "Behavioural: the server read, tampered with, or exfiltrated a decoy credential "
    "planted in the sandbox during enumeration.",
}


SCAN_ERROR_RULE = "scan-error"


def _rule_id(detector: str) -> str:
    return f"frisk/{detector}"


def _location(path: str, line: int) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": max(1, line)},
        }
    }


def _fingerprints(finding: Finding, server: str) -> dict[str, str]:
    """GitHub reads `primaryLocationLineHash` and nothing else, so that is where identity has
    to live. It is computed from the LOGICAL identity — the same tuple the baseline keys on —
    never from the text at the location, so editing an unrelated line of the config does not
    churn every alert closed and open again.

    The custom key is kept for consumers that read the whole map. Treat this tuple as a
    compatibility surface: changing what goes into it closes every existing alert and opens a
    duplicate.
    """
    key = "|".join(finding_key(finding, server))
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return {
        "primaryLocationLineHash": f"{digest}:1",
        "friskFindingKey/v2": key,
    }


def _rules_for(detectors: set[str], *, scan_error: bool) -> list[dict]:
    rules = [
        {
            "id": _rule_id(d),
            "name": DETECTOR_LABELS.get(d, d).replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": DETECTOR_LABELS.get(d, d)},
            "fullDescription": {"text": _RULE_HELP.get(d, DETECTOR_LABELS.get(d, d))},
            "help": {"text": _RULE_HELP.get(d, DETECTOR_LABELS.get(d, d))},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["security", "mcp"]},
        }
        for d in sorted(detectors)
    ]
    if scan_error:
        rules.append(
            {
                "id": _rule_id(SCAN_ERROR_RULE),
                "name": "ScanError",
                "shortDescription": {"text": "server could not be assessed"},
                "fullDescription": {
                    "text": "frisk could not enumerate this server, so none of its "
                    "definitions were inspected. An unassessed server is not a clean one."
                },
                "help": {"text": "Check that the server starts and completes the MCP handshake."},
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "mcp"]},
            }
        )
    return rules


def _document(rules: list[dict], results: list[dict], properties: dict) -> str:
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "frisk",
                        "version": __version__,
                        "informationUri": "https://github.com/Realgagenichols/frisk",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": True, "properties": properties}],
            }
        ],
    }
    # ensure_ascii keeps control characters escaped in the serialized form (R15).
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def render_sarif(
    inventory: Inventory,
    findings: list[Finding],
    assessment: Assessment,
    *,
    accepted: list[Finding] | None = None,
    stale: list[tuple[str, ...]] | None = None,
    fail_on: str | None = None,
    location_path: str = "frisk.lock",
) -> str:
    """One server, rendered as SARIF 2.1.0.

    ``location_path`` anchors the results. It defaults to the lockfile, which frisk writes
    into the workspace and which stands for the server that was scanned — GitHub requires a
    location and resolves it against the checkout, so it must be a path that exists there.

    Baselined findings are emitted with SARIF's ``suppressions`` rather than dropped, so
    GitHub shows them as accepted instead of pretending the server never advertised them —
    the same choice the human report makes.
    """
    detectors = {f.detector for f in findings} | {f.detector for f in (accepted or [])}
    results = [
        _result(f, server="", path=location_path, line=1, suppressed=False)
        for f in _ordered(findings)
    ]
    results += [
        _result(f, server="", path=location_path, line=1, suppressed=True)
        for f in _ordered(accepted or [])
    ]
    return _document(
        _rules_for(detectors, scan_error=False),
        results,
        {
            "verdict": assessment.verdict,
            "riskScore": assessment.score,
            "failOn": fail_on,
            "itemsScanned": len(inventory.items),
            "server": c0_escape(str(inventory.server_info.get("name", "(unnamed server)"))),
            "staleBaselineEntries": len(stale or []),
        },
    )


def render_multi_sarif(scans: list, config_path: str, *, fail_on: str | None = None) -> str:
    """A whole client config as ONE run (R36).

    One run, not one per server. A SARIF run is an alert-lifecycle slot: GitHub closes an
    alert when a later analysis under the same category no longer reports it. Uninstalling a
    bad MCP server is the most common remediation here, so it has to be the event that turns
    the alert green — and under one-run-per-server it would instead orphan that server's
    alerts forever, because no analysis for its category is ever uploaded again. (GitHub also
    rejects a file whose runs share a tool and category, and caps runs at 20.)

    Each result is located at the line of the config that declares its server, which is both
    a legal location and the line someone would delete to fix it.

    A server that failed to enumerate gets a synthetic ``frisk/scan-error`` result. Without
    one it would contribute zero findings, and the same auto-close behaviour that makes a
    single run correct would quietly close its previous alerts and show green for a server
    nobody assessed (R6).
    """
    from frisk.core.multi import ERROR, worst_verdict

    detectors: set[str] = set()
    results: list[dict] = []
    any_error = False
    for scan in scans:
        if scan.status == ERROR:
            any_error = True
            results.append(_scan_error_result(scan, config_path))
            continue
        if not scan.scanned:
            continue
        detectors |= {f.detector for f in scan.gating} | {f.detector for f in scan.accepted}
        for finding in _ordered(scan.gating):
            results.append(
                _result(
                    finding,
                    server=scan.name,
                    path=config_path,
                    line=scan.config_line,
                    suppressed=False,
                )
            )
        for finding in _ordered(scan.accepted):
            results.append(
                _result(
                    finding,
                    server=scan.name,
                    path=config_path,
                    line=scan.config_line,
                    suppressed=True,
                )
            )
    return _document(
        _rules_for(detectors, scan_error=any_error),
        results,
        {
            "verdict": worst_verdict(scans),
            "failOn": fail_on,
            "config": c0_escape(config_path),
            "serversScanned": sum(1 for s in scans if s.scanned),
            "serversFailed": sum(1 for s in scans if s.status == ERROR),
        },
    )


def _scan_error_result(scan, config_path: str) -> dict:
    digest = hashlib.sha256(f"scan-error|{scan.name}".encode()).hexdigest()[:32]
    return {
        "ruleId": _rule_id(SCAN_ERROR_RULE),
        "level": "error",
        "rank": _RANKS[Severity.HIGH],
        "message": {
            "text": (
                f"{c0_escape(scan.name)} could not be assessed: "
                f"{c0_escape(scan.error or 'enumeration failed')}. "
                "An unassessed server is not a clean one."
            )
        },
        "locations": [_location(config_path, scan.config_line)],
        "partialFingerprints": {
            "primaryLocationLineHash": f"{digest}:1",
            "friskFindingKey/v2": f"{scan.name}|scan-error",
        },
        "properties": {"server": c0_escape(scan.name), "status": "error"},
    }


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.detector, f.item_ref, f.field))


def _result(finding: Finding, *, server: str, path: str, line: int, suppressed: bool) -> dict:
    result: dict = {
        "ruleId": _rule_id(finding.detector),
        "level": _LEVELS[finding.severity],
        "rank": _RANKS[finding.severity],
        "message": {
            "text": (
                (f"[{c0_escape(server)}] " if server else "")
                + f"{c0_escape(finding.item_ref)} · {c0_escape(finding.field)}: "
                + c0_escape(finding.message)
            )
        },
        "locations": [_location(path, line)],
        "partialFingerprints": _fingerprints(finding, server),
        "properties": {
            "severity": finding.severity.name,
            "category": finding.evidence.category,
            "item": c0_escape(finding.item_ref),
            "field": c0_escape(finding.field),
        },
    }
    if server:
        result["properties"]["server"] = c0_escape(server)
    if finding.evidence.offset is not None:
        result["properties"]["byteOffset"] = finding.evidence.offset
    if finding.evidence.snippet is not None:
        # Already C0-escaped, truncated, and credential-masked by make_evidence (S3).
        result["properties"]["evidence"] = finding.evidence.snippet
    if suppressed:
        result["suppressions"] = [
            {"kind": "external", "justification": "accepted in the frisk baseline"}
        ]
    return result
