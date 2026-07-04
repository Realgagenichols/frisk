"""Normalize plain-dict MCP definitions into Inventory items — pure core (R21, R23).

Single source of truth for normalization and canonical bytes: the CLI connector delegates
here after ``model_dump``-ing the SDK models, and the playground's paste mode calls
``inventory_from_json`` directly. Keeping both paths on one implementation is what makes
paste-mode findings and lockfile hashes byte-identical to the CLI's.
"""

from __future__ import annotations

import json
from typing import Any

from frisk.core.models import Inventory, Item, ItemKind


class IngestError(Exception):
    """Malformed pasted/fetched definition JSON. The message names the exact problem and is
    safe to display: it never echoes input values (Pattern 11), only shapes and key names."""


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic canonical JSON of an advertised definition, for hashing + evidence (R5).

    ``sort_keys`` so re-enumeration produces byte-identical output for an unchanged
    definition (stable rug-pull baseline); ``ensure_ascii=False`` so hidden characters are
    preserved verbatim in the bytes rather than \\u-escaped away.
    """
    return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")


def tool_item(payload: dict[str, Any]) -> Item:
    name = _require_name(payload, "tool")
    return Item(
        kind=ItemKind.TOOL,
        name=name,
        description=_opt_str(payload, "description", "tool", name),
        input_schema=_opt_dict(payload, "inputSchema", "tool", name),
        raw_bytes=canonical_bytes(payload),
    )


def resource_item(payload: dict[str, Any]) -> Item:
    name = payload.get("name") or payload.get("uri")
    if not isinstance(name, str) or not name:
        raise IngestError("resource entry has neither a 'name' nor a 'uri' string")
    return Item(
        kind=ItemKind.RESOURCE,
        name=name,
        description=_opt_str(payload, "description", "resource", name),
        input_schema=None,
        raw_bytes=canonical_bytes(payload),
    )


def prompt_item(payload: dict[str, Any]) -> Item:
    name = _require_name(payload, "prompt")
    # Expose prompt arguments as a schema so D1/D3 scan their names + descriptions too.
    arguments = payload.get("arguments") or []
    if not isinstance(arguments, list):
        raise IngestError(f"prompt {name!r}: 'arguments' must be a list")
    properties: dict[str, Any] = {}
    for index, arg in enumerate(arguments):
        if not isinstance(arg, dict) or not isinstance(arg.get("name"), str):
            raise IngestError(f"prompt {name!r}: argument [{index}] needs a 'name' string")
        description = arg.get("description")
        properties[arg["name"]] = {
            "type": "string",
            **({"description": description} if description else {}),
        }
    schema = {"type": "object", "properties": properties} if properties else None
    return Item(
        kind=ItemKind.PROMPT,
        name=name,
        description=_opt_str(payload, "description", "prompt", name),
        input_schema=schema,
        raw_bytes=canonical_bytes(payload),
    )


def inventory_from_json(text: str) -> Inventory:
    """Build an Inventory from pasted/fetched definition JSON (R21).

    Accepted shapes:
    - a bare JSON array → treated as a list of tools;
    - an object with any subset of ``tools`` / ``resources`` / ``prompts`` arrays,
      plus optional ``serverInfo`` and ``instructions``;
    - a JSON-RPC envelope ``{"result": {...}}`` wrapping either of the above.

    Anything else raises IngestError with a specific, actionable message (Pattern 6) —
    a paste that can't be parsed must never render as a clean report.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # JSONDecodeError coordinates are safe; its message never embeds the document.
        raise IngestError(
            f"input is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
        ) from None

    if isinstance(data, dict) and "result" in data and (
        "jsonrpc" in data or isinstance(data["result"], dict)
    ):
        data = data["result"]

    if isinstance(data, list):
        data = {"tools": data}
    if not isinstance(data, dict):
        raise IngestError(
            f"expected a JSON object or array of tools, got {type(data).__name__}"
        )

    known = {k: data[k] for k in ("tools", "resources", "prompts") if k in data}
    if not known:
        raise IngestError(
            "no 'tools', 'resources', or 'prompts' array found — paste the JSON result of "
            "tools/list (or an object containing those keys)"
        )

    builders = {"tools": tool_item, "resources": resource_item, "prompts": prompt_item}
    items: list[Item] = []
    for key, entries in known.items():
        if not isinstance(entries, list):
            raise IngestError(f"'{key}' must be an array, got {type(entries).__name__}")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise IngestError(
                    f"'{key}[{index}]' must be an object, got {type(entry).__name__}"
                )
            items.append(builders[key](entry))

    return Inventory(
        items=items,
        server_info=_server_info(data),
        # A paste without a serverInfo key is a channel limitation, not a hygiene signal;
        # D7's missing-identity check only applies when the channel carried serverInfo.
        server_info_known="serverInfo" in data,
    )


def _server_info(data: dict[str, Any]) -> dict[str, Any]:
    info: dict[str, Any] = {}
    server = data.get("serverInfo")
    if isinstance(server, dict):
        for key in ("name", "version"):
            if isinstance(server.get(key), str):
                info[key] = server[key]
    if isinstance(data.get("instructions"), str) and data["instructions"]:
        info["instructions"] = data["instructions"]
    return info


def _require_name(payload: dict[str, Any], kind: str) -> str:
    name = payload.get("name")
    if not isinstance(name, str) or not name:
        raise IngestError(f"{kind} entry is missing a 'name' string")
    return name


def _opt_str(payload: dict[str, Any], key: str, kind: str, name: str) -> str | None:
    value = payload.get(key)
    if value is None or isinstance(value, str):
        return value
    raise IngestError(f"{kind} {name!r}: '{key}' must be a string")


def _opt_dict(payload: dict[str, Any], key: str, kind: str, name: str) -> dict[str, Any] | None:
    value = payload.get(key)
    if value is None or isinstance(value, dict):
        return value
    raise IngestError(f"{kind} {name!r}: '{key}' must be an object")
