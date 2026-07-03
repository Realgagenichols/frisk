"""Tests for core models and the raw-string leaf walker (R5, R12, Pattern 12)."""

import json

from frisk.core.models import (
    Evidence,
    Finding,
    Inventory,
    Item,
    ItemKind,
    Severity,
    iter_string_leaves,
)


def make_item(**kw) -> Item:
    defaults = dict(
        kind=ItemKind.TOOL,
        name="get_weather",
        description="Get the weather.",
        input_schema={"type": "object", "properties": {}},
        raw_bytes=b"{}",
    )
    defaults.update(kw)
    return Item(**defaults)


def test_severity_orders_and_maxes():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert max([Severity.LOW, Severity.HIGH, Severity.MEDIUM]) is Severity.HIGH
    assert str(Severity.HIGH) == "HIGH"


def test_item_ref():
    assert make_item(name="foo").ref == "tool:foo"
    assert make_item(kind=ItemKind.PROMPT, name="p").ref == "prompt:p"


def test_inventory_round_trip():
    item = make_item()
    inv = Inventory(items=[item], server_info={"name": "srv", "version": "1.0"})
    assert inv.items[0].name == "get_weather"
    assert inv.server_info["version"] == "1.0"


def test_finding_construction():
    f = Finding(
        detector="D1",
        severity=Severity.HIGH,
        item_ref="tool:foo",
        field="description",
        message="injection",
        evidence=Evidence(category="read-file", offset=3, span=(3, 8), snippet="read"),
    )
    assert f.severity is Severity.HIGH
    assert f.evidence.span == (3, 8)


def test_leaf_walker_yields_name_and_description():
    item = make_item(name="n", description="d", input_schema=None)
    leaves = dict(iter_string_leaves(item))
    assert leaves["name"] == "n"
    assert leaves["description"] == "d"
    assert "inputSchema" not in " ".join(leaves)  # no schema → no schema leaves


def test_leaf_walker_yields_property_names_and_values():
    schema = {
        "type": "object",
        "properties": {
            "full_conversation": {"type": "string", "description": "all history"},
        },
    }
    item = make_item(input_schema=schema)
    leaves = list(iter_string_leaves(item))
    # The property NAME is exposed as a leaf (needed by D3).
    assert ("inputSchema.properties.full_conversation", "full_conversation") in leaves
    # ...as is its nested description value.
    assert ("inputSchema.properties.full_conversation.description", "all history") in leaves


def test_leaf_walker_preserves_raw_control_chars_not_escaped():
    # Pattern 12: scanning a json.dumps blob would turn a tab into the 2 chars '\t' and a
    # newline into '\n', changing regex semantics. The walker must hand back the RAW string.
    raw = "line1\tafter-tab\nline2\"quote\""
    item = make_item(description=raw, input_schema=None)
    leaves = dict(iter_string_leaves(item))
    assert leaves["description"] == raw
    assert "\t" in leaves["description"] and "\n" in leaves["description"]
    # Prove it is NOT the escaped serialized form.
    assert leaves["description"] != json.dumps(raw)[1:-1]
    assert "\\t" not in leaves["description"]


def test_leaf_walker_walks_lists():
    schema = {"enum": ["alpha", "beta"]}
    item = make_item(input_schema=schema)
    values = [v for _, v in iter_string_leaves(item)]
    assert "alpha" in values and "beta" in values
