"""SARIF 2.1.0 output (R34) — the format GitHub code scanning ingests.

Uploading SARIF is how a scanner stops being a log line and starts being an annotation on
the pull request that introduced the problem. The mapping is deliberately conservative:

- one SARIF **rule** per detector, with a stable id (`frisk/D1`), so GitHub can track a
  finding across runs and a suppression in its UI keeps meaning the same thing;
- one **result** per finding;
- **no physical location.** SARIF locations are file/line, and frisk's findings are about a
  definition a remote server advertised — there is no file on disk to point at. Inventing a
  path would make the annotation land on an unrelated line of the repo. The item ref and
  field travel in `partialFingerprints` and the message instead, which is honest and still
  groups correctly.

Pure core, no I/O, no secret values (S3) — evidence carries categories and offsets, and the
snippet is already C0-escaped and credential-masked by `sanitize.make_evidence`.
"""

from __future__ import annotations

import json

from frisk import __version__
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


def _rule_id(detector: str) -> str:
    return f"frisk/{detector}"


def render_sarif(
    inventory: Inventory,
    findings: list[Finding],
    assessment: Assessment,
    *,
    accepted: list[Finding] | None = None,
    stale: list[tuple[str, str, str, str]] | None = None,
    fail_on: str | None = None,
) -> str:
    """Render findings as SARIF 2.1.0.

    Baselined findings are emitted with SARIF's own ``suppressions`` rather than dropped, so
    GitHub shows them as accepted instead of pretending the server never advertised them —
    the same choice the human report makes.
    """
    detectors = sorted({f.detector for f in findings} | {f.detector for f in (accepted or [])})
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
        for d in detectors
    ]

    results = [_result(f, suppressed=False) for f in _ordered(findings)]
    results += [_result(f, suppressed=True) for f in _ordered(accepted or [])]

    server = str(inventory.server_info.get("name", "(unnamed server)"))
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
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "verdict": assessment.verdict,
                            "riskScore": assessment.score,
                            "failOn": fail_on,
                            "itemsScanned": len(inventory.items),
                            "server": c0_escape(server),
                            "staleBaselineEntries": len(stale or []),
                        },
                    }
                ],
            }
        ],
    }
    # ensure_ascii keeps control characters escaped in the serialized form (R15).
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.detector, f.item_ref, f.field))


def _result(finding: Finding, *, suppressed: bool) -> dict:
    result: dict = {
        "ruleId": _rule_id(finding.detector),
        "level": _LEVELS[finding.severity],
        "rank": _RANKS[finding.severity],
        "message": {
            "text": (
                f"{c0_escape(finding.item_ref)} · {c0_escape(finding.field)}: "
                f"{c0_escape(finding.message)}"
            )
        },
        # The stable identity of a finding — the same tuple the baseline keys on, so a
        # suppression in GitHub's UI and an entry in frisk.baseline mean the same thing.
        "partialFingerprints": {
            "friskFindingKey/v1": "|".join(
                (finding.detector, finding.item_ref, finding.field, finding.evidence.category)
            )
        },
        "properties": {
            "severity": finding.severity.name,
            "category": finding.evidence.category,
            "item": c0_escape(finding.item_ref),
            "field": c0_escape(finding.field),
        },
    }
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
