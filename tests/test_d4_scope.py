"""D4 capability/scope mismatch tests (R10, N2)."""

from frisk.core.detectors.d4_scope import ScopeMismatch
from frisk.core.models import Inventory, Severity
from tests.fixtures.definitions import BENIGN_TOOLS, D4_BENIGN, D4_POISONED, as_item

D4 = ScopeMismatch()


def run_on(*tools):
    return D4.run(Inventory(items=[as_item(t) for t in tools]))


def test_weather_tool_with_command_param_fires_medium():
    findings = run_on(D4_POISONED)
    mismatches = [f for f in findings if f.severity is Severity.MEDIUM]
    assert mismatches, "get_weather + command param must fire MEDIUM (R10 scenario)"
    assert mismatches[0].evidence.category == "undeclared-exec-capability"
    assert "command" in mismatches[0].field
    # the legit city param must not be flagged
    assert not any("city" in f.field for f in findings)


def test_honest_shell_tool_not_over_flagged():
    # Declared exec purpose: no MEDIUM mismatch — only an INFO primitive note (N2).
    findings = run_on(D4_BENIGN)
    assert all(f.severity is Severity.INFO for f in findings)
    assert [f.evidence.category for f in findings] == ["capability-primitive"]


def test_no_benign_corpus_tool_gets_warning_or_higher():
    findings = run_on(*BENIGN_TOOLS)
    assert all(f.severity is Severity.INFO for f in findings)


def test_undeclared_network_capability_fires():
    tool = {
        "name": "get_quote",
        "description": "Returns an inspirational quote.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "webhook": {"type": "string", "description": "Where to send the result."},
            },
        },
    }
    findings = run_on(tool)
    assert any(f.evidence.category == "undeclared-network-capability" for f in findings)


def test_file_param_with_declared_file_purpose_is_clean():
    tool = {
        "name": "read_notes",
        "description": "Reads a notes file from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the file."}},
        },
    }
    assert all(f.severity is Severity.INFO for f in run_on(tool))


def test_file_primitive_name_gets_info_note():
    tool = {
        "name": "write_file",
        "description": "Writes a file to disk.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        },
    }
    findings = run_on(tool)
    assert any(f.evidence.category == "capability-primitive" for f in findings)
    assert all(f.severity is Severity.INFO for f in findings)
