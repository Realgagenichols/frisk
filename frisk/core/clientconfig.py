"""Parse an MCP client config into a list of servers to scan (R36).

The realistic question is not "is this one server safe" but "is my setup safe" — and the
answer lives in `claude_desktop_config.json` or `.mcp.json`, which already lists every server
someone has installed. Reading it directly is the difference between a tool you demo and a
tool you run.

Pure parsing, no I/O and no connector types, so the playground could use it too (R23). Both
observed shapes are accepted: `mcpServers` (Claude Desktop, Cursor, Windsurf) and `servers`
(VS Code). Unknown keys are ignored rather than rejected — this format grows, and refusing a
whole config over one unrecognised field would send people back to scanning by hand.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


class ConfigError(Exception):
    """A malformed client config. The message names the exact problem (R6)."""


@dataclass(frozen=True)
class ConfiguredServer:
    """One server declared in a client config."""

    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    disabled: bool = False

    @property
    def is_remote(self) -> bool:
        return self.url is not None


_SERVER_KEYS = ("mcpServers", "servers")


def parse_client_config(text: str) -> list[ConfiguredServer]:
    """Parse config JSON into servers, in declaration order.

    Order is preserved rather than sorted so the report reads in the same order as the file
    the user is looking at.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"config is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
        ) from None
    if not isinstance(doc, dict):
        raise ConfigError(f"config must be a JSON object, got {type(doc).__name__}")

    block: dict[str, Any] | None = None
    for key in _SERVER_KEYS:
        candidate = doc.get(key)
        if isinstance(candidate, dict):
            block = candidate
            break
    if block is None:
        raise ConfigError(
            "no 'mcpServers' or 'servers' object found — point --config at a client config "
            "such as claude_desktop_config.json or .mcp.json"
        )

    servers: list[ConfiguredServer] = []
    for name, raw in block.items():
        if not isinstance(raw, dict):
            raise ConfigError(f"server {name!r} must be an object, got {type(raw).__name__}")
        command = raw.get("command")
        url = raw.get("url") or raw.get("serverUrl")
        if command is not None and not isinstance(command, str):
            raise ConfigError(f"server {name!r}: 'command' must be a string")
        if url is not None and not isinstance(url, str):
            raise ConfigError(f"server {name!r}: 'url' must be a string")
        if command is None and url is None:
            raise ConfigError(f"server {name!r} declares neither a 'command' nor a 'url'")

        args = raw.get("args") or []
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ConfigError(f"server {name!r}: 'args' must be an array of strings")
        env = raw.get("env") or {}
        if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in env.items()
        ):
            raise ConfigError(f"server {name!r}: 'env' must be an object of strings")

        servers.append(
            ConfiguredServer(
                name=name,
                command=command,
                args=list(args),
                env=dict(env),
                url=url,
                # Both spellings appear in the wild; a disabled server is skipped, and the
                # report says so rather than silently omitting it.
                disabled=bool(raw.get("disabled") or raw.get("enabled") is False),
            )
        )
    if not servers:
        raise ConfigError("config declares no servers")
    return servers
