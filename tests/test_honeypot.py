"""Behavioral honeypot tests (R24): decoy seeding, access/tamper inspection, canary exfil."""

import json

from frisk.core.models import Inventory, Item, ItemKind, Severity
from frisk.sandbox import honeypot
from frisk.sandbox.honeypot import (
    DECOY_RELPATHS,
    inspect_decoys,
    scan_for_canary,
    seed_decoys,
)

# --- seeding (task 1.1–1.3) ------------------------------------------------------------------


def test_seed_creates_all_decoys_with_canary(tmp_path):
    decoys = seed_decoys(tmp_path)
    assert decoys.home == tmp_path
    assert set(decoys.baselines) == set(DECOY_RELPATHS)
    for relpath in DECOY_RELPATHS:
        path = tmp_path / relpath
        assert path.is_file(), relpath
        assert decoys.canary in path.read_text(encoding="utf-8"), relpath


def test_seed_decoy_content_is_realistic_shaped(tmp_path):
    decoys = seed_decoys(tmp_path)
    key = (tmp_path / ".ssh/id_rsa").read_text(encoding="utf-8")
    assert key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    aws = (tmp_path / ".aws/credentials").read_text(encoding="utf-8")
    assert "[default]" in aws and "aws_secret_access_key" in aws
    netrc = (tmp_path / ".netrc").read_text(encoding="utf-8")
    assert "machine" in netrc and "password" in netrc
    gh = (tmp_path / ".config/gh/hosts.yml").read_text(encoding="utf-8")
    assert "oauth_token" in gh
    del decoys


def test_seed_baseline_atime_is_epoch(tmp_path):
    """atime is pinned to epoch (< mtime) so even relatime-style mounts update on first
    read — and our own seeding/stat sequence must not have advanced it (task 1.3)."""
    decoys = seed_decoys(tmp_path)
    for relpath, baseline in decoys.baselines.items():
        assert baseline.atime_ns == 0, relpath
        assert baseline.mtime_ns > 0, relpath
        # Re-stat after seeding: our own bookkeeping did not count as an access.
        assert (tmp_path / relpath).stat().st_atime_ns == 0, relpath


def test_two_scans_get_different_canaries(tmp_path):
    a = seed_decoys(tmp_path / "a")
    b = seed_decoys(tmp_path / "b")
    assert a.canary != b.canary
    assert len(a.canary) >= 32  # long enough that accidental collision is implausible


def test_atime_capability_probe(tmp_path):
    """The probe reports whether this filesystem supports read detection; the probe file
    itself is removed so it never masquerades as a decoy."""
    decoys = seed_decoys(tmp_path)
    assert isinstance(decoys.atime_reliable, bool)
    leftover = [p for p in tmp_path.rglob("*") if "probe" in p.name.lower()]
    assert leftover == []


def test_atime_probe_false_when_utime_fails(tmp_path, monkeypatch):
    """A probe that cannot pin atime must report unreliable, never capable (fail loud)."""

    def broken_utime(*args, **kwargs):
        raise OSError("utime not supported")

    monkeypatch.setattr(honeypot.os, "utime", broken_utime)
    assert honeypot._probe_atime(tmp_path) is False


def test_atime_probe_false_when_pin_does_not_take(tmp_path, monkeypatch):
    """utime succeeding but not actually zeroing atime (coarse-atime mounts) must also
    report unreliable — setup failure must not masquerade as capability success."""
    monkeypatch.setattr(honeypot.os, "utime", lambda *a, **k: None)
    assert honeypot._probe_atime(tmp_path) is False


# --- access / tamper inspection (tasks 2.1–2.4) ----------------------------------------------


def test_untouched_decoys_yield_no_findings(tmp_path):
    decoys = seed_decoys(tmp_path)
    assert inspect_decoys(decoys) == []


def test_inspect_is_repeatable_without_self_tripping(tmp_path):
    """The inspector's own stat calls must not count as access (N2 / benign-twin, and the
    'most ordinary event that could trip the rule' treatment)."""
    decoys = seed_decoys(tmp_path)
    assert inspect_decoys(decoys) == []
    assert inspect_decoys(decoys) == []  # a second pass stays clean too


def test_reading_a_decoy_fires_decoy_access(tmp_path):
    decoys = seed_decoys(tmp_path)
    if not decoys.atime_reliable:  # pragma: no cover — dev machines have atime
        import pytest

        pytest.skip("filesystem does not support atime-based access detection")
    (tmp_path / ".ssh/id_rsa").read_text(encoding="utf-8")
    findings = inspect_decoys(decoys)
    assert len(findings) == 1
    f = findings[0]
    assert (f.detector, f.severity) == ("D8", Severity.HIGH)
    assert f.item_ref == "honeypot:.ssh/id_rsa"
    assert f.evidence.category == "decoy-access"
    # S3: evidence and message never carry decoy file contents.
    assert decoys.canary not in f.message
    assert f.evidence.snippet is None


def test_modifying_a_decoy_fires_decoy_tamper_not_access(tmp_path):
    decoys = seed_decoys(tmp_path)
    path = tmp_path / ".netrc"
    with path.open("a", encoding="utf-8") as fh:
        fh.write("machine evil.example\n")
    findings = inspect_decoys(decoys)
    refs = [(f.item_ref, f.evidence.category) for f in findings]
    assert refs == [("honeypot:.netrc", "decoy-tamper")]  # tamper subsumes access


def test_deleting_a_decoy_fires_decoy_tamper(tmp_path):
    decoys = seed_decoys(tmp_path)
    (tmp_path / ".aws/credentials").unlink()
    findings = inspect_decoys(decoys)
    assert [(f.item_ref, f.evidence.category, f.severity) for f in findings] == [
        ("honeypot:.aws/credentials", "decoy-tamper", Severity.HIGH)
    ]


def test_replacing_a_decoy_parent_dir_fires_decoy_tamper(tmp_path):
    """ENOTDIR is tampering, not an inspection error: `mv ~/.ssh aside; touch ~/.ssh` makes
    the decoy path vanish just as thoroughly as deleting the file (§2 review)."""
    import shutil

    decoys = seed_decoys(tmp_path)
    shutil.rmtree(tmp_path / ".ssh")
    (tmp_path / ".ssh").write_text("not a dir", encoding="utf-8")
    findings = inspect_decoys(decoys)
    assert [(f.item_ref, f.evidence.category, f.severity) for f in findings] == [
        ("honeypot:.ssh/id_rsa", "decoy-tamper", Severity.HIGH)
    ]


def test_stat_error_is_a_finding_never_a_silent_pass(tmp_path, monkeypatch):
    """R12: a detector that errors emits a finding — never silently passes."""
    decoys = seed_decoys(tmp_path)
    real_stat = honeypot.os.stat

    def flaky_stat(path, *args, **kwargs):
        if str(path).endswith(".netrc"):
            raise PermissionError("stat denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(honeypot.os, "stat", flaky_stat)
    findings = inspect_decoys(decoys)
    assert [(f.item_ref, f.evidence.category, f.severity) for f in findings] == [
        ("honeypot:.netrc", "honeypot-error", Severity.INFO)
    ]
    assert "PermissionError" in findings[0].message  # actionable, type-name only


def test_finding_item_refs_are_unique_per_decoy(tmp_path):
    """Lesson: evidence anchors need unique paths — one decoy → one distinct item_ref."""
    decoys = seed_decoys(tmp_path)
    for relpath in DECOY_RELPATHS:
        p = tmp_path / relpath
        if p.exists():
            p.unlink()
    findings = inspect_decoys(decoys)
    refs = [f.item_ref for f in findings]
    assert len(refs) == len(set(refs)) == len(DECOY_RELPATHS)


# --- exfiltration canary scan (tasks 3.1–3.2) -------------------------------------------------


def _item(name: str, description: str) -> Item:
    payload = {"name": name, "description": description, "inputSchema": {"type": "object"}}
    return Item(
        kind=ItemKind.TOOL,
        name=name,
        description=description,
        input_schema=payload["inputSchema"],
        raw_bytes=json.dumps(payload).encode("utf-8"),
    )


def test_canary_in_tool_description_fires_critical(tmp_path):
    decoys = seed_decoys(tmp_path)
    item = _item("sync_notes", f"Syncs notes. debug={decoys.canary}")
    inventory = Inventory(items=[_item("get_weather", "Weather by city."), item])
    findings = scan_for_canary(inventory, decoys)
    assert len(findings) == 1
    f = findings[0]
    assert (f.detector, f.severity) == ("D8", Severity.CRITICAL)
    assert f.item_ref == "tool:sync_notes"
    assert f.evidence.category == "canary-exfiltration"
    assert f.evidence.offset == item.raw_bytes.find(decoys.canary.encode())
    # S3: the canary (decoy credential material) never appears in message or snippet.
    assert decoys.canary not in f.message
    assert f.evidence.snippet is None


def test_canary_in_server_instructions_fires_critical(tmp_path):
    decoys = seed_decoys(tmp_path)
    inventory = Inventory(
        items=[_item("get_weather", "Weather by city.")],
        server_info={"name": "srv", "instructions": f"token cache: {decoys.canary}"},
    )
    findings = scan_for_canary(inventory, decoys)
    assert [(f.item_ref, f.field, f.severity) for f in findings] == [
        ("(server)", "serverInfo.instructions", Severity.CRITICAL)
    ]


def test_aws_access_key_fragment_alone_is_detected(tmp_path):
    """The AWS decoy's access-key-id carries only AKIA + a 16-char canary fragment; a thief
    exfiltrating just the key id must still be caught (§1 review note)."""
    decoys = seed_decoys(tmp_path)
    fragment = "AKIA" + decoys.canary[:16].upper()
    inventory = Inventory(items=[_item("backup", f"Backs up. id={fragment}")])
    findings = scan_for_canary(inventory, decoys)
    assert [(f.item_ref, f.evidence.category) for f in findings] == [
        ("tool:backup", "canary-exfiltration")
    ]


def test_lookalike_hex_is_not_flagged(tmp_path):
    """N2 false-positive twin: a hex string of identical length/shape that is NOT this
    scan's canary (e.g. a legitimate commit SHA) must not fire."""
    decoys = seed_decoys(tmp_path)
    other = seed_decoys(tmp_path / "other")  # a different scan's canary: same shape
    sha = "d4c3b2a1" * 5  # 40 hex chars, commit-SHA shaped
    inventory = Inventory(
        items=[
            _item("git_log", f"Shows commits like {sha}."),
            _item("sync", f"debug={other.canary}"),
        ]
    )
    assert scan_for_canary(inventory, decoys) == []


def test_one_finding_per_item_even_with_multiple_hits(tmp_path):
    decoys = seed_decoys(tmp_path)
    inventory = Inventory(
        items=[_item("leak", f"a={decoys.canary} b={decoys.canary}")],
    )
    findings = scan_for_canary(inventory, decoys)
    assert len(findings) == 1  # first offset only; one item, one finding


def test_server_info_offset_is_bytes_not_chars(tmp_path):
    """Evidence.offset is a byte offset in the field's UTF-8 encoding (models.py contract);
    a non-ASCII prefix must not drift it (§3 review)."""
    decoys = seed_decoys(tmp_path)
    instructions = f"サーバー説明 token: {decoys.canary}"
    inventory = Inventory(
        items=[], server_info={"name": "srv", "instructions": instructions}
    )
    findings = scan_for_canary(inventory, decoys)
    assert len(findings) == 1
    expected = instructions.encode("utf-8").find(decoys.canary.encode("utf-8"))
    assert findings[0].evidence.offset == expected
    assert expected != instructions.find(decoys.canary)  # the two units genuinely differ


def test_item_finding_field_is_raw(tmp_path):
    decoys = seed_decoys(tmp_path)
    inventory = Inventory(items=[_item("leak", f"x={decoys.canary}")])
    assert scan_for_canary(inventory, decoys)[0].field == "raw"


def test_verify_honeypot_line_escapes_server_controlled_item_ref():
    """R15 (§4 review): the verify stderr line is the only Finding sink outside the core
    renderers; a canary finding's item_ref embeds a server-controlled tool name, so ANSI
    and newlines must be escaped before reaching the terminal."""
    from frisk.cli import _honeypot_line
    from frisk.core.models import Evidence, Finding

    hostile = Finding(
        detector="D8",
        severity=Severity.CRITICAL,
        item_ref="tool:evil\x1b[2K\nfaked-clean-line",
        field="raw",
        message="decoy credential material in advertised definition (exfiltration attempt)",
        evidence=Evidence(category="canary-exfiltration", offset=0),
    )
    line = _honeypot_line(hostile)
    assert "\x1b" not in line and "\n" not in line
    assert "\\u001b" in line or "\\x1b" in line  # escaped, not stripped — evidence intact
