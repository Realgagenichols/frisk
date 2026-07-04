"""Connect, handshake, enumerate, normalize — with loud, token-safe failure (R1–R6, S3)."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

from frisk.connector.target import RemoteTarget, StdioTarget, Target
from frisk.core.models import Inventory, Item, ItemKind


class ConnectorError(Exception):
    """A connection or enumeration failure. Its message is safe to print: it names the phase
    and the exception *type* only — never target bytes, exception reprs, or auth tokens
    (cross-cutting Pattern 11, S3)."""


def enumerate_target(target: Target, *, timeout: float | None = None) -> Inventory:
    """Synchronously enumerate a target into an Inventory. Fails loudly (R6): on any error it
    raises ConnectorError — it never returns a partial or empty Inventory that a caller might
    mistake for a clean 'no findings' result. ``timeout`` is a hard wall-clock bound on the
    whole handshake+enumeration (the sandbox's outer containment, R4)."""
    import anyio

    try:
        return anyio.run(_enumerate, target, timeout)
    except ConnectorError:
        raise
    except BaseException as exc:  # noqa: BLE001 — boundary: convert to a safe, loud error
        raise ConnectorError(
            f"could not enumerate {target.label}: {_root_cause_name(exc)}"
        ) from None


def _root_cause_name(exc: BaseException) -> str:
    """Unwrap ExceptionGroups to a concrete cause and return only its type name (Pattern 11)."""
    seen = 0
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions and seen < 10:
        exc = exc.exceptions[0]
        seen += 1
    return type(exc).__name__


async def _enumerate(target: Target, timeout: float | None = None) -> Inventory:
    import anyio

    if timeout is not None:
        with anyio.fail_after(timeout):
            return await _enumerate_inner(target)
    return await _enumerate_inner(target)


async def _enumerate_inner(target: Target) -> Inventory:
    from mcp import ClientSession

    async with _open_transport(target) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            try:
                init = await session.initialize()
            except Exception as exc:
                raise ConnectorError(
                    f"MCP initialize handshake failed for {target.label}: {type(exc).__name__}"
                ) from None

            caps = init.capabilities
            items: list[Item] = []
            if getattr(caps, "tools", None) is not None:
                result = await _guard(session.list_tools(), "list tools", target)
                items.extend(_tool_item(t) for t in result.tools)
            if getattr(caps, "resources", None) is not None:
                result = await _guard(session.list_resources(), "list resources", target)
                items.extend(_resource_item(r) for r in result.resources)
            if getattr(caps, "prompts", None) is not None:
                result = await _guard(session.list_prompts(), "list prompts", target)
                items.extend(_prompt_item(p) for p in result.prompts)

            return Inventory(items=items, server_info=_server_info(init))


async def _guard(coro: Any, phase: str, target: Target) -> Any:
    try:
        return await coro
    except Exception as exc:
        raise ConnectorError(
            f"failed to {phase} for {target.label}: {type(exc).__name__}"
        ) from None


@asynccontextmanager
async def _open_transport(target: Target):
    if isinstance(target, StdioTarget):
        from mcp import StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=target.command,
            args=list(target.args),
            env=dict(target.env),
            cwd=target.cwd,
        )
        async with stdio_client(params) as (read_stream, write_stream):
            yield read_stream, write_stream
    elif isinstance(target, RemoteTarget):
        headers = (
            {"Authorization": f"Bearer {target.auth_token}"} if target.auth_token else None
        )
        transport = target.transport
        if transport in ("auto", "http"):
            import mcp.client.streamable_http as sh

            # The SDK renamed streamablehttp_client → streamable_http_client; support both.
            http_client = getattr(sh, "streamable_http_client", None) or sh.streamablehttp_client
            async with http_client(target.url, headers=headers) as streams:
                # streamable-http yields (read, write, get_session_id)
                yield streams[0], streams[1]
        elif transport == "sse":
            from mcp.client.sse import sse_client

            async with sse_client(target.url, headers=headers) as (read_stream, write_stream):
                yield read_stream, write_stream
        else:
            raise ConnectorError(f"unknown transport {transport!r} for {target.label}")
    else:  # pragma: no cover — exhaustive
        raise ConnectorError(f"unsupported target type: {type(target).__name__}")


def _canonical_bytes(model: Any) -> bytes:
    """Deterministic canonical JSON of an advertised definition, for hashing + evidence (R5).

    Uses ``sort_keys`` so re-enumeration produces byte-identical output for an unchanged
    definition (stable rug-pull baseline), and ``ensure_ascii=False`` so hidden characters
    are preserved verbatim in the bytes rather than \\u-escaped away.
    """
    payload = model.model_dump(mode="json", exclude_none=True)
    return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")


def _tool_item(tool: Any) -> Item:
    return Item(
        kind=ItemKind.TOOL,
        name=tool.name,
        description=tool.description,
        input_schema=tool.inputSchema,
        raw_bytes=_canonical_bytes(tool),
    )


def _resource_item(resource: Any) -> Item:
    return Item(
        kind=ItemKind.RESOURCE,
        name=resource.name or str(resource.uri),
        description=resource.description,
        input_schema=None,
        raw_bytes=_canonical_bytes(resource),
    )


def _prompt_item(prompt: Any) -> Item:
    # Expose prompt arguments as a schema so D1/D3 scan their names + descriptions too.
    arguments = getattr(prompt, "arguments", None) or []
    properties = {
        arg.name: {
            "type": "string",
            **({"description": arg.description} if arg.description else {}),
        }
        for arg in arguments
    }
    schema = {"type": "object", "properties": properties} if properties else None
    return Item(
        kind=ItemKind.PROMPT,
        name=prompt.name,
        description=prompt.description,
        input_schema=schema,
        raw_bytes=_canonical_bytes(prompt),
    )


def _server_info(init: Any) -> dict[str, Any]:
    info: dict[str, Any] = {}
    server = getattr(init, "serverInfo", None)
    if server is not None:
        info["name"] = getattr(server, "name", None)
        info["version"] = getattr(server, "version", None)
    instructions = getattr(init, "instructions", None)
    if instructions:
        info["instructions"] = instructions
    return {k: v for k, v in info.items() if v is not None}
