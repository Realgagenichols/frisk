"""Report rendering: human-readable and JSON (R17), terminal-injection-safe (R15).

Lives in the core (not the CLI) so the Pyodide playground renders the identical report
(R23). Every server-derived value — item names, field paths, snippets — is C0-escaped at
render time: a tool name containing ANSI or newlines must not be able to forge or hide
report lines (cross-cutting Pattern 13). JSON output uses ``ensure_ascii=True`` so control
characters are always escaped in the serialized form.
"""

from __future__ import annotations

import json
from collections import Counter

from frisk import __version__
from frisk.core.models import Finding, Inventory, ItemKind
from frisk.core.sanitize import c0_escape
from frisk.core.score import Assessment

DETECTOR_LABELS = {
    "D1": "instruction-injection",
    "D2": "hidden-content",
    "D3": "sensitive-params",
    "D4": "scope-mismatch",
    "D5": "shadowing",
    "D6": "rug-pull",
    "D7": "metadata-hygiene",
    # D8 findings are produced by the CLI-side honeypot (frisk.sandbox.honeypot), not by an
    # Inventory detector — the label lives here so both renderers name it consistently.
    "D8": "honeypot",
}


def render_human(
    inventory: Inventory,
    findings: list[Finding],
    assessment: Assessment,
    *,
    accepted: list[Finding] | None = None,
    stale: list[tuple[str, ...]] | None = None,
    fail_on: str | None = None,
) -> str:
    lines: list[str] = []
    server = c0_escape(str(inventory.server_info.get("name", "(unnamed server)")))
    kind_counts = Counter(item.kind for item in inventory.items)
    inventory_desc = ", ".join(
        f"{kind_counts.get(kind, 0)} {kind.value}s" for kind in ItemKind
    )
    lines.append(f"frisk report — {server} ({inventory_desc})")

    sev_counts = Counter(f.severity for f in findings)
    counts_desc = (
        ", ".join(
            f"{sev_counts[sev]} {sev.name}"
            for sev in sorted(sev_counts, reverse=True)
        )
        or "none"
    )
    lines.append(
        f"verdict: {assessment.verdict.upper()}  |  risk score: {assessment.score}/100"
        f"  |  findings: {counts_desc}"
    )
    # State the gate in the report. An exit 0 whose reason lives only in the CI config is a
    # mystery to whoever reads the log six months later.
    gate = []
    if fail_on:
        gate.append(f"failing at {fail_on.upper()} and above")
    if accepted:
        gate.append(f"{len(accepted)} accepted via baseline")
    if gate:
        lines.append("gate: " + "  |  ".join(gate))
    lines.append("")

    for f in sorted(findings, key=lambda f: (-f.severity, f.detector, f.item_ref, f.field)):
        label = DETECTOR_LABELS.get(f.detector, f.detector)
        where = f"{c0_escape(f.item_ref)} · {c0_escape(f.field)}"
        if f.evidence.offset is not None:
            where += f" @ byte {f.evidence.offset}"
        lines.append(f"[{f.severity.name}] {f.detector} {label} — {where}")
        lines.append(f"    {c0_escape(f.message)}")
        detail = f"    ({c0_escape(f.evidence.category)})"
        if f.evidence.snippet is not None:
            detail += f' "{c0_escape(f.evidence.snippet)}"'
        lines.append(detail)

    if not findings:
        lines.append("no findings")

    # Accepted findings are LISTED, not hidden. A baseline changes what fails the build; a
    # report that omitted them would misdescribe what the server actually advertises.
    if accepted:
        lines.append("")
        lines.append(f"accepted via baseline ({len(accepted)}) — reported, not gating:")
        for f in sorted(accepted, key=lambda f: (-f.severity, f.detector, f.item_ref, f.field)):
            lines.append(
                f"  [{f.severity.name}] {f.detector} — {c0_escape(f.item_ref)} · "
                f"{c0_escape(f.field)} ({c0_escape(f.evidence.category)})"
            )
    if stale:
        lines.append("")
        lines.append(
            f"stale baseline entries ({len(stale)}) — accepted, but no longer present. "
            "Remove them so the baseline keeps meaning something:"
        )
        for server, detector, item_ref, field_path, category in stale:
            where = f"{c0_escape(server)} / " if server else ""
            lines.append(
                f"  {where}{c0_escape(detector)} — {c0_escape(item_ref)} · "
                f"{c0_escape(field_path)} ({c0_escape(category)})"
            )
    return "\n".join(lines) + "\n"


def _finding_doc(f: Finding) -> dict:
    return {
        "detector": f.detector,
        "severity": f.severity.name,
        "item": f.item_ref,
        "field": f.field,
        "message": f.message,
        "evidence": {
            "category": f.evidence.category,
            "offset": f.evidence.offset,
            "span": list(f.evidence.span) if f.evidence.span else None,
            "snippet": f.evidence.snippet,
        },
    }


def render_json(
    inventory: Inventory,
    findings: list[Finding],
    assessment: Assessment,
    *,
    accepted: list[Finding] | None = None,
    stale: list[tuple[str, ...]] | None = None,
    fail_on: str | None = None,
) -> str:
    doc = {
        "frisk_version": __version__,
        "verdict": assessment.verdict,
        "risk_score": assessment.score,
        "highest_severity": assessment.highest.name if assessment.highest else None,
        "items_scanned": len(inventory.items),
        "server_info": inventory.server_info,
        "fail_on": fail_on,
        "accepted": [
            _finding_doc(f)
            for f in sorted(
                accepted or [], key=lambda f: (-f.severity, f.detector, f.item_ref, f.field)
            )
        ],
        "stale_baseline_entries": [
            {"server": srv, "detector": d, "item": i, "field": f, "category": c}
            for srv, d, i, f, c in (stale or [])
        ],
        "findings": [
            _finding_doc(f)
            for f in sorted(
                findings, key=lambda f: (-f.severity, f.detector, f.item_ref, f.field)
            )
        ],
    }
    # ensure_ascii keeps every control character escaped in the serialized output (R15).
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
