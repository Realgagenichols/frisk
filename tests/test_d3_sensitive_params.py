"""D3 sensitive-parameter capture tests (R9, N2)."""

from frisk.core.detectors.d3_sensitive_params import SensitiveParams
from frisk.core.models import Inventory, Severity
from tests.fixtures.definitions import BENIGN_TOOLS, D3_BENIGN, D3_POISONED, as_item

D3 = SensitiveParams()


def run_on(*tools):
    return D3.run(Inventory(items=[as_item(t) for t in tools]))


def test_full_conversation_param_fires_medium_naming_property():
    findings = run_on(D3_POISONED)
    conv = [f for f in findings if f.evidence.category == "conversation-history"]
    assert conv, "must fire on full_conversation"
    assert all(f.severity is Severity.MEDIUM for f in findings)
    # R9 scenario: names THAT property.
    assert any("full_conversation" in f.field for f in conv)


def test_env_and_credential_params_fire():
    findings = run_on(D3_POISONED)
    categories = {f.evidence.category for f in findings}
    assert "environment-capture" in categories
    assert "credential-solicitation" in categories
    assert any("api_key" in f.field for f in findings)


def test_benign_bounded_context_not_flagged():
    # "context" bounded by an enum is a narrow, legitimate parameter (N2, Pattern 2).
    assert run_on(D3_BENIGN) == []


def test_no_benign_corpus_tool_fires():
    assert run_on(*BENIGN_TOOLS) == []


def test_unbounded_context_catchall_fires():
    tool = {
        "name": "t",
        "description": "d",
        "inputSchema": {
            "type": "object",
            "properties": {"context": {"type": "string", "description": "Anything useful."}},
        },
    }
    findings = run_on(tool)
    assert [f.evidence.category for f in findings] == ["generic-catchall"]


def test_max_tokens_is_not_a_credential():
    tool = {
        "name": "complete",
        "description": "Text completion.",
        "inputSchema": {
            "type": "object",
            "properties": {"max_tokens": {"type": "integer", "description": "Length cap."}},
        },
    }
    assert run_on(tool) == []


def test_schema_without_properties_is_fine():
    tool = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
    assert run_on(tool) == []
