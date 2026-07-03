"""Detector framework: protocol, error-to-finding wrapping, overlap suppression (R12, N1).

Pure and deterministic — no network, no LLM, no I/O — so it runs identically in the CLI and
under Pyodide (R23).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from frisk.core.models import Evidence, Finding, Inventory, Severity


@runtime_checkable
class Detector(Protocol):
    """A deterministic rule that inspects an Inventory and emits Findings."""

    id: str  # e.g. "D1"

    def run(self, inventory: Inventory) -> list[Finding]: ...


def run_detectors(inventory: Inventory, detectors: list[Detector] | None = None) -> list[Finding]:
    """Run detectors over an inventory: errors become findings, overlaps are suppressed.

    A detector that raises yields a HIGH "detector errored" finding — never a silent pass
    (R12, Pattern 6). Only the exception *type* is reported: detector input is untrusted, and
    exception reprs can echo it (Pattern 11).
    """
    if detectors is None:
        from frisk.core.detectors import ALL_DETECTORS

        detectors = ALL_DETECTORS
    findings: list[Finding] = []
    for detector in detectors:
        try:
            findings.extend(detector.run(inventory))
        except Exception as exc:  # noqa: BLE001 — boundary: error must become a finding
            findings.append(_error_finding(detector, exc))
    return suppress_overlaps(findings)


def _error_finding(detector: Detector, exc: Exception) -> Finding:
    detector_id = getattr(detector, "id", detector.__class__.__name__)
    return Finding(
        detector=detector_id,
        severity=Severity.HIGH,
        item_ref="(scan)",
        field="(detector)",
        message=(
            f"detector {detector_id} errored ({type(exc).__name__}); "
            "results for this rule are incomplete"
        ),
        evidence=Evidence(category="detector-error"),
    )


def suppress_overlaps(findings: list[Finding]) -> list[Finding]:
    """Most-specific match wins on overlapping spans of the same item field (R12, Pattern 1).

    Precedence: higher severity first (a HIGH must never be hidden by a MEDIUM), then longer
    span (specific patterns capture more context than generic ones), then detector id for
    determinism. A finding whose span overlaps an already-kept finding on the same
    (item_ref, field) is suppressed. Findings without spans never participate.
    """
    spanned = [f for f in findings if f.evidence.span is not None]
    unspanned = [f for f in findings if f.evidence.span is None]

    def precedence(f: Finding) -> tuple:
        # Total order: message/category break ties so the survivor never depends on
        # input order, even for two same-detector patterns matching the same span.
        start, end = f.evidence.span  # type: ignore[misc]
        return (-f.severity, -(end - start), f.detector, start, f.evidence.category, f.message)

    kept: list[Finding] = []
    for finding in sorted(spanned, key=precedence):
        span = finding.evidence.span
        assert span is not None
        clashes = any(
            k.item_ref == finding.item_ref
            and k.field == finding.field
            and _overlaps(k.evidence.span, span)  # type: ignore[arg-type]
            for k in kept
        )
        if not clashes:
            kept.append(finding)

    result = unspanned + kept
    result.sort(key=lambda f: (f.item_ref, f.field, f.evidence.span or (-1, -1), f.detector))
    return result


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]
