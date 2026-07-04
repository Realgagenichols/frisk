"""Behavioral honeypot tests (R24): decoy seeding, access/tamper inspection, canary exfil."""

from frisk.sandbox.honeypot import DECOY_RELPATHS, seed_decoys

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
