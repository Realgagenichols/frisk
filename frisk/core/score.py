"""Risk scoring and verdict (R13) and the CI exit-code gate (R18).

Pure and deterministic: the same findings always produce the same score, verdict, and exit
code, in the CLI and under Pyodide alike.
"""

from __future__ import annotations

from dataclasses import dataclass

from frisk.core.models import Finding, Severity

# Weighted contribution of each finding to the 0–100 risk score. INFO is informational
# only; a single CRITICAL should dominate a pile of LOWs.
WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 15,
    Severity.CRITICAL: 30,
}

MAX_SCORE = 100


@dataclass(frozen=True)
class Assessment:
    score: int  # 0 (clean) .. 100 (maximum risk)
    verdict: str  # "pass" | "warn" | "fail"
    highest: Severity | None  # None when there are no findings


def assess(findings: list[Finding]) -> Assessment:
    """Aggregate findings into a weighted score and an overall verdict (R13)."""
    score = min(MAX_SCORE, sum(WEIGHTS[f.severity] for f in findings))
    highest = max((f.severity for f in findings), default=None)
    if highest is None or highest is Severity.INFO:
        verdict = "pass"
    elif highest <= Severity.MEDIUM:
        verdict = "warn"
    else:
        verdict = "fail"
    return Assessment(score=score, verdict=verdict, highest=highest)


def exit_code(assessment: Assessment) -> int:
    """CI gate (R18): 0 clean, 1 warnings (LOW/MEDIUM), 2 HIGH/CRITICAL."""
    return {"pass": 0, "warn": 1, "fail": 2}[assessment.verdict]
