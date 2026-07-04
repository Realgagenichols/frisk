"""Playground glue loaded into Pyodide by app.js (R20, R23).

Site-glue only — zero detector logic. It calls the exact same core pipeline the CLI runs:
inventory_from_json → run_detectors → assess → render_json/render_human. The returned
envelope tells JS whether the paste parsed (ok) or which specific IngestError to display.
"""

import json

from frisk.core.engine import run_detectors
from frisk.core.ingest import IngestError, inventory_from_json
from frisk.core.report import render_human, render_json
from frisk.core.score import assess, exit_code


def scan_json(text: str) -> str:
    try:
        inventory = inventory_from_json(text)
    except IngestError as exc:
        return json.dumps({"ok": False, "error": str(exc)})
    findings = run_detectors(inventory)
    assessment = assess(findings)
    return json.dumps(
        {
            "ok": True,
            "report": json.loads(render_json(inventory, findings, assessment)),
            "human": render_human(inventory, findings, assessment),
            "exit_code": exit_code(assessment),
            "server_info_known": inventory.server_info_known,
        }
    )
