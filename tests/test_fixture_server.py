"""Fixture MCP server harness tests (N3) — the harness the connector/sandbox tests rely on."""

import json
import os
import sys

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def _enumerate(mode: str):
    env = dict(os.environ, FRISK_FIXTURE_MODE=mode, PYTHONPATH=REPO_ROOT)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tests.fixtures.mcp_server"],
        env=env,
        cwd=REPO_ROOT,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            prompts = (await session.list_prompts()).prompts
            return tools, prompts


def test_simple_mode_advertises_three_tools_one_prompt():
    tools, prompts = anyio.run(_enumerate, "simple")
    assert len(tools) == 3 and len(prompts) == 1  # R2 enumeration scenario


def test_poisoned_mode_preserves_hidden_characters():
    tools, _ = anyio.run(_enumerate, "poisoned")
    by_name = {t.name: t for t in tools}
    # The zero-width smuggled instruction must survive the MCP serialization round-trip.
    assert "\u200b" in by_name["get_time"].description
    assert "\x1b" in by_name["get_date"].description


def test_mutated_mode_differs_from_benign_in_one_description():
    benign, _ = anyio.run(_enumerate, "benign")
    mutated, _ = anyio.run(_enumerate, "mutated")
    benign_desc = {t.name: t.description for t in benign}
    diffs = [t.name for t in mutated if benign_desc.get(t.name) != t.description]
    assert len(diffs) == 1


def test_exit_handshake_mode_fails_before_initialize():
    with pytest.raises(BaseException):  # noqa: B017,PT011 — MCP raises an ExceptionGroup
        anyio.run(_enumerate, "exit-handshake")


def test_probe_records_network_and_home_outcomes(tmp_path, monkeypatch):
    from tests.fixtures import mcp_server

    result = tmp_path / "probe.json"
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("FRISK_PROBE_RESULT", str(result))
    monkeypatch.setenv("HOME", str(fake_home))
    mcp_server._run_probe()
    outcome = json.loads(result.read_text())
    assert "network" in outcome and "ssh_key_contents" in outcome
    # No real key under the fake HOME → unreadable, never the real user's key.
    assert outcome["ssh_key_contents"].startswith("unreadable")
    assert outcome["home"] == str(fake_home)
