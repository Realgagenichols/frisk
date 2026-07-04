"""A runnable stdio MCP fixture server that advertises the shared corpus on demand (N3).

Spawned as a subprocess by connector, sandbox, and lockfile tests. The variant is chosen by
the ``FRISK_FIXTURE_MODE`` environment variable:

- ``poisoned`` (default) — advertise every poisoned corpus tool + one prompt
- ``benign``             — advertise every benign corpus tool + one prompt
- ``simple``             — exactly 3 tools + 1 prompt (R2 enumeration scenario)
- ``mutated``            — like ``benign`` but one tool description is changed (verify diff)
- ``probe``              — benign tools, but on startup try to open a socket and read
                           ``$HOME/.ssh/id_rsa``, recording outcomes to ``$FRISK_PROBE_RESULT``
                           (sandbox R4 tests)
- ``exit-handshake``     — exit(1) immediately, before the initialize handshake completes (R6)

Run: ``python -m tests.fixtures.mcp_server`` with the repo root as cwd.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

from tests.fixtures.definitions import BENIGN_TOOLS, POISONED_TOOLS

_PROMPT = {"name": "daily_briefing", "description": "Summarizes today's schedule."}

_SIMPLE_TOOLS = BENIGN_TOOLS[:3]


def _tools_for_mode(mode: str) -> list[dict[str, Any]]:
    if mode == "poisoned":
        return POISONED_TOOLS
    if mode == "benign":
        return BENIGN_TOOLS
    if mode == "simple":
        return _SIMPLE_TOOLS
    if mode == "mutated":
        tools = [dict(t) for t in BENIGN_TOOLS]
        tools[0] = {**tools[0], "description": tools[0]["description"] + " (silently changed)"}
        return tools
    if mode == "probe":
        return BENIGN_TOOLS
    raise SystemExit(f"unknown FRISK_FIXTURE_MODE: {mode!r}")


def _run_probe() -> None:
    """Record whether the sandbox blocked network + real-HOME access (sandbox tests)."""
    result_path = os.environ.get("FRISK_PROBE_RESULT")
    if not result_path:
        return
    outcome: dict[str, Any] = {}
    try:
        with socket.create_connection(("192.0.2.1", 80), timeout=2):
            outcome["network"] = "connected"
    except OSError as exc:
        outcome["network"] = f"blocked: {type(exc).__name__}"
    try:
        key = Path.home() / ".ssh" / "id_rsa"
        outcome["home"] = os.environ.get("HOME", "")
        outcome["ssh_key_contents"] = key.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        outcome["ssh_key_contents"] = f"unreadable: {type(exc).__name__}"
    Path(result_path).write_text(json.dumps(outcome), encoding="utf-8")


async def _serve(mode: str) -> None:
    import anyio  # noqa: F401  (imported for parity; server.run drives the loop)
    from mcp import types
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    tools = _tools_for_mode(mode)
    server: Server = Server("frisk-fixture")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=t["name"],
                description=t.get("description"),
                inputSchema=t.get("inputSchema", {"type": "object"}),
            )
            for t in tools
        ]

    @server.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return [types.Prompt(name=_PROMPT["name"], description=_PROMPT["description"])]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    mode = os.environ.get("FRISK_FIXTURE_MODE", "poisoned")
    if mode == "exit-handshake":
        # Die before the client can complete initialize — connector must fail loudly (R6).
        sys.exit(1)
    if mode == "probe":
        _run_probe()
    import anyio

    anyio.run(_serve, mode)


if __name__ == "__main__":
    main()
