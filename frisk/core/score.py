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

# A server can reach a saturated 100/100 on MEDIUMs alone and still be called `warn`, because
# the verdict read only the single highest severity. Six tools impersonating built-in names,
# each soliciting credentials and conversation history, is not a warning. The threshold is set
# where accumulated risk is unarguable and far above anything honest: the full benign corpus
# scores 0, and the worst realistic benign server measured scores 10.
FAIL_SCORE = 50


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
    elif highest > Severity.MEDIUM or score >= FAIL_SCORE:
        verdict = "fail"
    else:
        verdict = "warn"
    return Assessment(score=score, verdict=verdict, highest=highest)


DEFAULT_FAIL_ON = Severity.HIGH


def exit_code(assessment: Assessment, fail_on: Severity = DEFAULT_FAIL_ON) -> int:
    """CI gate (R18, R32): 0 clean, 1 findings below the threshold, 2 at or above it.

    ``fail_on`` moves only the line between 1 and 2 — nothing is hidden from the report by
    raising it, and nothing new is detected by lowering it. The default is HIGH, which is the
    original contract exactly.

    The accumulated-score rule (R13) is expressed as a promotion of the effective severity
    rather than a separate branch: a saturated pile of MEDIUMs is a HIGH-equivalent, so it
    fails at the default and still does not fail under ``--fail-on critical``, which is what
    someone asking only to be woken for CRITICALs meant.
    """
    if assessment.highest is None or assessment.highest is Severity.INFO:
        return 0
    effective = assessment.highest
    if assessment.verdict == "fail" and effective < Severity.HIGH:
        effective = Severity.HIGH
    return 2 if effective >= fail_on else 1


def parse_fail_on(name: str) -> Severity:
    """Map a `--fail-on` argument to a Severity. Raises ValueError on an unknown name."""
    try:
        return Severity[name.strip().upper()]
    except KeyError:
        raise ValueError(f"unknown severity {name!r}") from None
