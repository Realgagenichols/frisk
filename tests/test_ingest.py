"""Ingest tests: accepted paste shapes, loud malformed-input failures, and byte-for-byte
parity with the connector's normalization (R21, R23)."""

import json

import pytest

from frisk.connector.enumerate import _prompt_item, _resource_item, _tool_item
from frisk.core.engine import run_detectors
from frisk.core.ingest import IngestError, inventory_from_json
from frisk.core.models import Inventory, ItemKind, Severity
from tests.fixtures.definitions import (
    BENIGN_TOOLS,
    D2_POISONED_ZERO_WIDTH,
    D7_BENIGN_SERVER_INFO,
    POISONED_TOOLS,
    as_item,
)

SIMPLE_TOOL = {
    "name": "get_weather",
    "description": "Returns the weather for a city.",
    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
}


# --- accepted shapes (R21) -------------------------------------------------------------------


def test_bare_array_is_treated_as_tools():
    inv = inventory_from_json(json.dumps([SIMPLE_TOOL]))
    assert [i.kind for i in inv.items] == [ItemKind.TOOL]
    assert inv.items[0].name == "get_weather"


def test_tools_object_shape():
    inv = inventory_from_json(json.dumps({"tools": [SIMPLE_TOOL]}))
    assert len(inv.items) == 1


def test_full_object_with_resources_and_prompts():
    payload = {
        "tools": [SIMPLE_TOOL],
        "resources": [{"uri": "file:///readme", "name": "readme", "description": "Docs."}],
        "prompts": [
            {
                "name": "summarize",
                "description": "Summarize text.",
                "arguments": [{"name": "text", "description": "Text to summarize."}],
            }
        ],
    }
    inv = inventory_from_json(json.dumps(payload))
    kinds = [i.kind for i in inv.items]
    assert kinds == [ItemKind.TOOL, ItemKind.RESOURCE, ItemKind.PROMPT]
    # Prompt arguments become a scannable schema, same as the connector does (R5).
    assert "text" in inv.items[2].input_schema["properties"]


def test_jsonrpc_envelope_is_unwrapped():
    envelope = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [SIMPLE_TOOL]}}
    inv = inventory_from_json(json.dumps(envelope))
    assert len(inv.items) == 1


def test_server_info_and_instructions_captured():
    payload = {
        "tools": [SIMPLE_TOOL],
        "serverInfo": {"name": "weather-server", "version": "1.0.0"},
        "instructions": "Use for weather only.",
    }
    inv = inventory_from_json(json.dumps(payload))
    assert inv.server_info == {
        "name": "weather-server",
        "version": "1.0.0",
        "instructions": "Use for weather only.",
    }
    assert inv.server_info_known


def test_resource_falls_back_to_uri_when_name_missing():
    inv = inventory_from_json(json.dumps({"resources": [{"uri": "file:///a.txt"}]}))
    assert inv.items[0].name == "file:///a.txt"


# --- malformed input fails loudly (Pattern 6) --------------------------------------------------


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("{not json", "not valid JSON"),
        ("42", "expected a JSON object or array"),
        ('{"stuff": []}', "no 'tools', 'resources', or 'prompts'"),
        ('{"tools": {}}', "'tools' must be an array"),
        ('{"tools": [42]}', "'tools[0]' must be an object"),
        ('{"tools": [{"description": "no name"}]}', "missing a 'name'"),
        ('{"tools": [{"name": "x", "inputSchema": "nope"}]}', "'inputSchema' must be an object"),
        ('{"tools": [{"name": "x", "description": 7}]}', "'description' must be a string"),
        ('{"prompts": [{"name": "p", "arguments": "no"}]}', "'arguments' must be a list"),
        ('{"prompts": [{"name": "p", "arguments": [{}]}]}', "argument [0] needs a 'name'"),
        ('{"resources": [{"description": "d"}]}', "neither a 'name' nor a 'uri'"),
    ],
)
def test_malformed_input_raises_specific_ingest_error(text, fragment):
    with pytest.raises(IngestError) as excinfo:
        inventory_from_json(text)
    assert fragment in str(excinfo.value)


def test_json_error_message_does_not_echo_document_content():
    # Pattern 11: the sentinel from the bad paste must not appear in the error message.
    with pytest.raises(IngestError) as excinfo:
        inventory_from_json('{"tools": [SENTINEL-hunter2')
    assert "hunter2" not in str(excinfo.value)


# --- connector parity (R23) --------------------------------------------------------------------


def test_tool_parity_with_connector_normalization():
    from mcp.types import Tool

    model = Tool(**SIMPLE_TOOL)
    via_connector = _tool_item(model)
    via_ingest = inventory_from_json(json.dumps({"tools": [SIMPLE_TOOL]})).items[0]
    assert via_connector.raw_bytes == via_ingest.raw_bytes
    assert via_connector == via_ingest


def test_prompt_and_resource_parity_with_connector():
    from mcp.types import Prompt, PromptArgument, Resource

    prompt_dict = {
        "name": "summarize",
        "description": "Summarize text.",
        "arguments": [{"name": "text", "description": "Text to summarize.", "required": True}],
    }
    resource_dict = {"uri": "file:///readme", "name": "readme", "description": "Docs."}

    prompt_model = Prompt(
        name="summarize",
        description="Summarize text.",
        arguments=[PromptArgument(name="text", description="Text to summarize.", required=True)],
    )
    resource_model = Resource(uri="file:///readme", name="readme", description="Docs.")

    inv = inventory_from_json(json.dumps({"prompts": [prompt_dict], "resources": [resource_dict]}))
    by_kind = {i.kind: i for i in inv.items}
    assert _prompt_item(prompt_model) == by_kind[ItemKind.PROMPT]
    assert _resource_item(resource_model) == by_kind[ItemKind.RESOURCE]


def test_poisoned_paste_findings_match_direct_pipeline():
    """The same poisoned corpus pasted as JSON (with \\uXXXX-escaped hidden chars — the form
    a real clipboard paste of ``ensure_ascii`` output takes) must produce exactly the findings
    the connector-normalized path produces (R23, Pattern 12)."""
    pasted = json.dumps(  # ensure_ascii=True: hidden chars travel as \uXXXX and decode back
        {"tools": POISONED_TOOLS, "serverInfo": dict(D7_BENIGN_SERVER_INFO)}
    )
    assert "\\u200b" in pasted and "\u200b" not in pasted

    via_ingest = inventory_from_json(pasted)
    direct = Inventory(
        items=[as_item(t) for t in POISONED_TOOLS],
        server_info=dict(D7_BENIGN_SERVER_INFO),
    )
    assert run_detectors(via_ingest) == run_detectors(direct)
    # Sanity: the corpus actually fires, including D2 on the decoded zero-width channel.
    detectors = {f.detector for f in run_detectors(via_ingest)}
    assert {"D1", "D2"} <= detectors


def test_hidden_chars_decode_from_escapes_before_scanning():
    inv = inventory_from_json(json.dumps({"tools": [D2_POISONED_ZERO_WIDTH]}))
    assert "\u200b" in inv.items[0].description  # raw char, not the 6-char escape sequence


# --- benign twin (N2) ----------------------------------------------------------------------


def test_benign_paste_with_vendor_extras_is_clean():
    """An ordinary tools/list paste — no serverInfo (bare list channel), one tool carrying
    legit vendor extras — parses fine and produces zero findings."""
    decorated = {
        **BENIGN_TOOLS[0],
        "annotations": {"title": "Read notes", "readOnlyHint": True},
        "x-vendor-build": "2026.07.01",
    }
    inv = inventory_from_json(json.dumps({"tools": [decorated, *BENIGN_TOOLS[1:]]}))
    assert not inv.server_info_known
    findings = run_detectors(inv)
    # D4_BENIGN (run_shell) legitimately draws its by-design INFO note; nothing else may fire.
    assert [f for f in findings if f.severity > Severity.INFO] == []
    assert all(f.item_ref == "tool:run_shell" for f in findings)


def test_missing_server_identity_still_flagged_when_channel_carried_it():
    # The D7 missing-identity signal must survive for pastes that DO include serverInfo.
    inv = inventory_from_json(json.dumps({"tools": BENIGN_TOOLS, "serverInfo": {"name": "x"}}))
    assert any(
        f.detector == "D7" and f.evidence.category == "missing-server-identity"
        for f in run_detectors(inv)
    )
