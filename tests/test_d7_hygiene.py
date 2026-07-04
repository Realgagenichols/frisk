"""D7 metadata hygiene tests (R16, N2)."""

from frisk.core.detectors.d7_hygiene import MetadataHygiene
from frisk.core.models import Inventory, Severity
from tests.fixtures.definitions import (
    BENIGN_TOOLS,
    D7_BENIGN,
    D7_BENIGN_SERVER_INFO,
    D7_POISONED,
    D7_POISONED_SERVER_INFO,
    as_item,
)

D7 = MetadataHygiene()


def run_on(tools, server_info):
    return D7.run(Inventory(items=[as_item(t) for t in tools], server_info=server_info))


def test_remote_unpinned_code_fires_low():
    findings = run_on([D7_POISONED], D7_BENIGN_SERVER_INFO)
    assert [f.evidence.category for f in findings] == ["remote-unpinned-code"]
    assert findings[0].severity is Severity.LOW


def test_missing_server_identity_fires_low():
    findings = run_on([D7_BENIGN], D7_POISONED_SERVER_INFO)
    assert [f.evidence.category for f in findings] == ["missing-server-identity"]
    assert "name" in findings[0].message and "version" in findings[0].message


def test_benign_pinned_identified_server_clean():
    assert run_on([D7_BENIGN], D7_BENIGN_SERVER_INFO) == []


def test_no_benign_corpus_tool_fires():
    assert run_on(BENIGN_TOOLS, D7_BENIGN_SERVER_INFO) == []


def test_docs_link_is_not_remote_code():
    tool = {
        "name": "get_weather",
        "description": "Returns weather. See https://docs.example.com for API details.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    assert run_on([tool], D7_BENIGN_SERVER_INFO) == []
