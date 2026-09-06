"""Client-config parsing (R36).

The realistic question is "is my setup safe", and the answer already exists in
`claude_desktop_config.json`. These cover the shapes seen in the wild and the failure modes
that must be loud.
"""

import json

import pytest

from frisk.core.clientconfig import ConfigError, parse_client_config

pytestmark = pytest.mark.regression


def config(**servers) -> str:
    return json.dumps({"mcpServers": servers})


def test_parses_the_claude_desktop_shape():
    servers = parse_client_config(
        config(
            weather={"command": "npx", "args": ["-y", "@acme/weather"], "env": {"TZ": "UTC"}},
        )
    )
    assert len(servers) == 1
    s = servers[0]
    assert s.name == "weather" and s.command == "npx"
    assert s.args == ["-y", "@acme/weather"] and s.env == {"TZ": "UTC"}
    assert not s.is_remote and not s.disabled


def test_parses_the_vs_code_servers_key():
    servers = parse_client_config(json.dumps({"servers": {"a": {"command": "x"}}}))
    assert [s.name for s in servers] == ["a"]


def test_declaration_order_is_preserved():
    """The report reads in the same order as the file the user is looking at."""
    servers = parse_client_config(
        config(zebra={"command": "z"}, alpha={"command": "a"}, mid={"command": "m"})
    )
    assert [s.name for s in servers] == ["zebra", "alpha", "mid"]


def test_remote_servers_are_recognised():
    servers = parse_client_config(config(remote={"url": "https://mcp.example.com/mcp"}))
    assert servers[0].is_remote and servers[0].url.startswith("https://")


@pytest.mark.parametrize(
    "raw", [{"command": "x", "disabled": True}, {"command": "x", "enabled": False}]
)
def test_both_disabled_spellings_are_honoured(raw):
    assert parse_client_config(config(off=raw))[0].disabled


def test_unknown_keys_are_ignored_rather_than_rejected():
    """This format grows. Refusing a whole config over one unrecognised field would send
    people back to scanning servers by hand, which is the thing this replaces."""
    servers = parse_client_config(
        config(a={"command": "x", "someFutureKey": {"nested": True}, "type": "stdio"})
    )
    assert servers[0].command == "x"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{not json", "not valid JSON"),
        ("[]", "must be a JSON object"),
        ('{"other": {}}', "no 'mcpServers' or 'servers'"),
        ('{"mcpServers": {}}', "declares no servers"),
        ('{"mcpServers": {"a": "string"}}', "must be an object"),
        ('{"mcpServers": {"a": {}}}', "neither a 'command' nor a 'url'"),
        ('{"mcpServers": {"a": {"command": 5}}}', "'command' must be a string"),
        ('{"mcpServers": {"a": {"command": "x", "args": "no"}}}', "'args' must be an array"),
        ('{"mcpServers": {"a": {"command": "x", "env": {"K": 1}}}}', "'env' must be an object"),
    ],
)
def test_malformed_configs_fail_loudly_and_specifically(text, expected):
    with pytest.raises(ConfigError) as excinfo:
        parse_client_config(text)
    assert expected in str(excinfo.value)


# ── what goes into an UPLOADED document (S3) ────────────────────────────────


def test_a_config_inside_the_workspace_is_published_relative(tmp_path):
    from frisk.core.multi import sarif_config_path

    config = tmp_path / "sub" / ".mcp.json"
    config.parent.mkdir()
    config.write_text("{}", encoding="utf-8")
    path, inside = sarif_config_path(str(config), str(tmp_path))
    assert path == "sub/.mcp.json" and inside is True


def test_a_config_outside_the_workspace_is_published_as_a_basename(tmp_path):
    """A SARIF file gets UPLOADED. `/Users/<name>/Library/.../claude_desktop_config.json`
    publishes the operating-system username to anyone who can read the repository's security
    tab — and the README's own example points at a home-directory config, so this is the
    common path, not an exotic one."""
    from frisk.core.multi import sarif_config_path

    outside = tmp_path / "elsewhere" / "claude_desktop_config.json"
    outside.parent.mkdir()
    outside.write_text("{}", encoding="utf-8")
    workspace = tmp_path / "repo"
    workspace.mkdir()
    path, inside = sarif_config_path(str(outside), str(workspace))
    assert path == "claude_desktop_config.json" and inside is False
    assert "/" not in path and str(tmp_path) not in path
