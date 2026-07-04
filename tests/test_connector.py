"""Connector tests: handshake, enumeration, remote token safety, fail-loud (R1-R6, S3)."""

import os
import sys

import pytest

from frisk.connector import (
    ConnectorError,
    RemoteTarget,
    StdioTarget,
    enumerate_target,
)
from frisk.core.models import ItemKind

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fixture_target(mode: str, **kw) -> StdioTarget:
    env = dict(os.environ, FRISK_FIXTURE_MODE=mode, PYTHONPATH=REPO_ROOT)
    return StdioTarget(
        command=sys.executable,
        args=["-m", "tests.fixtures.mcp_server"],
        env=env,
        cwd=REPO_ROOT,
        **kw,
    )


def test_stdio_handshake_and_enumeration_counts():
    # R1 handshake + R2 scenario: 3 tools + 1 prompt → 4-item inventory.
    inv = enumerate_target(fixture_target("simple"))
    assert len(inv.items) == 4
    kinds = [i.kind for i in inv.items]
    assert kinds.count(ItemKind.TOOL) == 3
    assert kinds.count(ItemKind.PROMPT) == 1


def test_inventory_captures_name_description_schema_and_raw_bytes():
    # R5: per item name, description, inputSchema, and raw advertised bytes.
    inv = enumerate_target(fixture_target("simple"))
    tool = next(i for i in inv.items if i.kind is ItemKind.TOOL)
    assert tool.name and tool.description is not None
    assert tool.input_schema is not None
    assert isinstance(tool.raw_bytes, bytes) and tool.raw_bytes


def test_server_info_captured_for_hygiene_checks():
    inv = enumerate_target(fixture_target("simple"))
    assert inv.server_info.get("name") == "frisk-fixture"


def test_poisoned_hidden_chars_survive_into_inventory():
    inv = enumerate_target(fixture_target("poisoned"))
    get_time = next(i for i in inv.items if i.name == "get_time")
    assert "\u200b" in (get_time.description or "")  # zero-width preserved (R5)


def test_handshake_exit_fails_loudly_not_clean():
    # R6: a server that dies during handshake must raise, never return an empty inventory.
    with pytest.raises(ConnectorError) as excinfo:
        enumerate_target(fixture_target("exit-handshake"))
    msg = str(excinfo.value)
    assert "stdio:" in msg  # names the target
    # Fail-loud, not "0 findings": the error is specific, not a silent empty result.
    assert msg  # non-empty, actionable


def test_nonexistent_command_fails_loudly():
    target = StdioTarget(command="/nonexistent/frisk-no-such-binary", args=[])
    with pytest.raises(ConnectorError):
        enumerate_target(target)


def test_remote_auth_token_never_appears_in_error_output():
    # R3/S3: a bad remote target must fail loudly, and the token must never surface.
    secret = "super-secret-bearer-TOKEN-xyz"
    target = RemoteTarget(
        url="http://127.0.0.1:1/mcp",  # nothing is listening → connection error
        auth_token=secret,
        transport="http",
    )
    with pytest.raises(ConnectorError) as excinfo:
        enumerate_target(target)
    assert secret not in str(excinfo.value)
    assert secret not in repr(target)  # repr=False on the token field (Pattern 11)


def test_remote_target_label_hides_query_and_token():
    target = RemoteTarget(url="https://api.example.com/mcp?token=abc", auth_token="t")
    assert "token=abc" not in target.label
    assert target.label == "remote:https://api.example.com"
