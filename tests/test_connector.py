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
from frisk.core.models import ItemKind, iter_string_leaves

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
    # R1 handshake + R2: "enumerate tools, RESOURCES, and prompts". The fixture advertises
    # 3 tools + 1 resource + 1 prompt; the resources branch of the connector had no coverage
    # at all until the fixture served one, so ItemKind.RESOURCE only ever arrived via paste.
    inv = enumerate_target(fixture_target("simple"))
    kinds = [i.kind for i in inv.items]
    assert kinds.count(ItemKind.TOOL) == 3
    assert kinds.count(ItemKind.RESOURCE) == 1
    assert kinds.count(ItemKind.PROMPT) == 1
    assert len(inv.items) == 5


def test_enumerated_resource_carries_its_uri_and_mimetype():
    # R5 for resources: the fields a detector needs must survive the connector's model_dump.
    inv = enumerate_target(fixture_target("simple"))
    resource = next(i for i in inv.items if i.kind is ItemKind.RESOURCE)
    assert resource.name == "today_notes"
    assert resource.payload.get("uri", "").startswith("file:///notes/")
    assert resource.payload.get("mimeType") == "text/markdown"
    assert dict(iter_string_leaves(resource)).get("uri", "").startswith("file:///notes/")


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
    # Fail-loud, not "0 findings": the message must name the PHASE and a concrete cause, not
    # merely be non-empty — `assert msg` passed for any string at all.
    assert "could not enumerate" in msg or "handshake failed" in msg
    assert msg.rstrip().endswith(("Error", "Exception", "Group")), msg  # a cause type, named


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


@pytest.mark.regression
def test_remote_new_style_client_receives_bearer_via_http_client(monkeypatch):
    # Regression: mcp>=1.28 renamed streamablehttp_client → streamable_http_client and
    # replaced the headers kwarg with a caller-supplied httpx client. Passing headers=
    # raised TypeError on every remote scan; the token must arrive via the httpx client.
    from contextlib import asynccontextmanager

    import anyio
    import mcp.client.streamable_http as sh

    from frisk.connector.enumerate import _open_transport

    seen = {}

    @asynccontextmanager
    async def fake_client(url, *, http_client=None, terminate_on_close=True):
        seen["auth"] = http_client.headers.get("Authorization") if http_client else None
        yield ("r", "w", lambda: None)

    monkeypatch.setattr(sh, "streamable_http_client", fake_client, raising=False)

    async def run():
        target = RemoteTarget(url="https://api.example.com/mcp", auth_token="tok")
        async with _open_transport(target) as (read_stream, write_stream):
            assert (read_stream, write_stream) == ("r", "w")

    anyio.run(run)
    assert seen["auth"] == "Bearer tok"


def test_remote_target_label_hides_query_and_token():
    target = RemoteTarget(url="https://api.example.com/mcp?token=abc", auth_token="t")
    assert "token=abc" not in target.label
    assert target.label == "remote:https://api.example.com"
