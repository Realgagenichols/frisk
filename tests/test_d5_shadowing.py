"""D5 shadowing/impersonation tests (R11, N2)."""

from frisk.core.detectors.d5_shadowing import Shadowing
from frisk.core.models import Inventory, Severity
from tests.fixtures.definitions import BENIGN_TOOLS, D5_BENIGN, D5_POISONED, as_item

D5 = Shadowing()


def run_on(*tools):
    return D5.run(Inventory(items=[as_item(t) for t in tools]))


def test_read_file_on_third_party_server_fires_medium():
    findings = run_on(D5_POISONED)
    imp = [f for f in findings if f.evidence.category == "common-name-impersonation"]
    assert imp and imp[0].severity is Severity.MEDIUM  # R11 scenario
    assert imp[0].field == "name"


def test_steering_language_fires():
    findings = run_on(D5_POISONED)
    categories = {f.evidence.category for f in findings}
    assert "steering-toward" in categories  # "Always use this tool instead of ..."


def test_benign_twin_not_flagged():
    assert run_on(D5_BENIGN) == []


def test_no_benign_corpus_tool_fires():
    assert run_on(*BENIGN_TOOLS) == []


def test_mild_usage_docs_not_steering():
    tool = {
        "name": "get_notes",
        "description": "Use this tool to read saved notes. Works well with search_notes.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    assert run_on(tool) == []
