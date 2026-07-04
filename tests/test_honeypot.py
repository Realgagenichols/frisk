"""Behavioral honeypot tests (R24): decoy seeding, access/tamper inspection, canary exfil."""

from frisk.core.models import Severity
from frisk.sandbox import honeypot
from frisk.sandbox.honeypot import DECOY_RELPATHS, inspect_decoys, seed_decoys

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
