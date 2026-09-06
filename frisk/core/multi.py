"""One scan result per configured server, and the JSON shape for a whole config (R36).

`--config` scans N servers, and the three outcomes are not two: a server is **scanned**,
**disabled** in the config, or **failed to enumerate**. That third state is the one that
matters — "could not be assessed" is never "clean" (R6) — and a flat merged list of findings
cannot express it, because a server that failed contributes zero findings and so looks
exactly like a server that came back clean.

So the JSON shape is an envelope with a per-server entry, deliberately different from the
SARIF shape. The two have different consumers: SARIF answers to GitHub's alert database,
whose lifecycle rules dictate a single merged run; JSON answers to a `jq` script asking
"which server do I uninstall", which needs the per-server verdict a merge destroys. A
consumer can flatten a nested document; it cannot un-flatten a merged one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from frisk import __version__
from frisk.core.baseline import FindingKey
from frisk.core.models import Finding, Inventory
from frisk.core.report import _finding_doc
from frisk.core.sanitize import c0_escape
from frisk.core.score import Assessment

SCANNED = "scanned"
DISABLED = "disabled"
ERROR = "error"


@dataclass
class ServerScan:
    """One configured server's outcome."""

    name: str
    status: str = SCANNED
    inventory: Inventory | None = None
    assessment: Assessment | None = None
    gating: list[Finding] = field(default_factory=list)
    accepted: list[Finding] = field(default_factory=list)
    stale: list[FindingKey] = field(default_factory=list)
    error: str | None = None
    # 1-based line in the config where this server is declared, for SARIF annotation.
    config_line: int = 1

    @property
    def scanned(self) -> bool:
        return self.status == SCANNED


def config_line_of(config_text: str, server_name: str) -> int:
    """The 1-based line where a server key is declared.

    `json.loads` discards positions, so this is a raw-text scan for the quoted key. It is
    used only to point an annotation at the right line; a miss falls back to line 1 rather
    than failing, because a slightly-off annotation is much better than no report.
    """
    needle = json.dumps(server_name)  # quoted and escaped exactly as it appears in the file
    for number, line in enumerate(config_text.splitlines(), start=1):
        if needle in line:
            return number
    return 1


def render_multi_json(scans: list[ServerScan], config_path: str, *, fail_on: str | None) -> str:
    """Per-server envelope. Every server appears, including the ones that never ran."""
    servers: list[dict[str, Any]] = []
    for scan in scans:
        entry: dict[str, Any] = {"name": scan.name, "status": scan.status}
        if scan.status == ERROR:
            entry["error"] = scan.error
        elif scan.scanned and scan.assessment is not None:
            entry.update(
                {
                    "verdict": scan.assessment.verdict,
                    "risk_score": scan.assessment.score,
                    "highest_severity": (
                        scan.assessment.highest.name if scan.assessment.highest else None
                    ),
                    "items_scanned": len(scan.inventory.items) if scan.inventory else 0,
                    "server_info": scan.inventory.server_info if scan.inventory else {},
                    "findings": [_finding_doc(f) for f in _ordered(scan.gating)],
                    "accepted": [_finding_doc(f) for f in _ordered(scan.accepted)],
                    "stale_baseline_entries": [
                        {"server": srv, "detector": d, "item": i, "field": f, "category": c}
                        for srv, d, i, f, c in scan.stale
                    ],
                }
            )
        servers.append(entry)

    doc = {
        "frisk_version": __version__,
        "config": config_path,
        "fail_on": fail_on,
        "verdict": worst_verdict(scans),
        "servers_scanned": sum(1 for s in scans if s.scanned),
        "servers_failed": sum(1 for s in scans if s.status == ERROR),
        "servers": servers,
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def worst_verdict(scans: list[ServerScan]) -> str:
    """The verdict for a whole config. A server that could not be assessed makes the config
    a `fail`: an unknown is not a pass (R6)."""
    if any(s.status == ERROR for s in scans):
        return "fail"
    order = {"pass": 0, "warn": 1, "fail": 2}
    verdicts = [s.assessment.verdict for s in scans if s.assessment is not None]
    return max(verdicts, key=lambda v: order[v], default="pass")


def render_multi_human(scans: list[ServerScan], config_path: str, *, fail_on: str | None) -> str:
    """Section per server, in declaration order, so the report reads like the file."""
    from frisk.core.report import render_human

    header = (
        f"frisk — {len(scans)} server{'' if len(scans) == 1 else 's'} from "
        f"{c0_escape(config_path)}\n\n"
    )
    sections: list[str] = []
    for scan in scans:
        title = f"═══ {c0_escape(scan.name)} ═══"
        if scan.status == DISABLED:
            sections.append(f"{title}\ndisabled in the config — not scanned\n")
        elif scan.status == ERROR:
            sections.append(f"{title}\nERROR: {c0_escape(scan.error or '')}\n")
        else:
            sections.append(
                title
                + "\n"
                + render_human(
                    scan.inventory,
                    scan.gating,
                    scan.assessment,
                    accepted=scan.accepted,
                    stale=scan.stale,
                    fail_on=fail_on,
                )
            )
    return header + "\n".join(sections)


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.detector, f.item_ref, f.field))
