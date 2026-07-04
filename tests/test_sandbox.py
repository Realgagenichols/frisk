"""Sandbox tests (R4, R4a). The seatbelt tests are macOS-only and skip elsewhere."""

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from frisk.connector import ConnectorError, StdioTarget, enumerate_target
from frisk.sandbox import (
    SandboxOptions,
    prepare_stdio,
    scrub_env,
    seatbelt_available,
)
from frisk.sandbox.prepare import build_profile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
requires_seatbelt = pytest.mark.skipif(
    not seatbelt_available(), reason="seatbelt (sandbox-exec) not available on this platform"
)


def _probe_target(result_file: Path, fake_home: Path, extra_env=None) -> StdioTarget:
    env = {
        "FRISK_FIXTURE_MODE": "probe",
        "FRISK_PROBE_RESULT": str(result_file),
        "PYTHONPATH": REPO_ROOT,
        **(extra_env or {}),
    }
    return StdioTarget(
        command=sys.executable,
        args=["-m", "tests.fixtures.mcp_server"],
        env=env,
        cwd=REPO_ROOT,
    )


def _run_probe(target, result_file, timeout):
    enumerate_target(target, timeout=timeout)
    return json.loads(result_file.read_text())


@pytest.fixture
def local_listener():
    """A localhost TCP listener that accepts one connection — proves connectivity is
    otherwise possible, so a 'blocked' result is meaningful."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def accept_loop():
        try:
            srv.settimeout(10)
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_loop, daemon=True).start()
    yield host, port
    srv.close()


# --- scrub_env (unit, cross-platform) -------------------------------------------------------


def test_scrub_env_drops_ambient_secrets_keeps_allowlist():
    ambient = {"PATH": "/usr/bin", "AWS_SECRET_ACCESS_KEY": "sk-live-xyz", "OPENAI_API_KEY": "k"}
    scrubbed = scrub_env({"FRISK_FIXTURE_MODE": "probe"}, Path("/fake"), ambient)
    assert scrubbed["PATH"] == "/usr/bin"
    assert scrubbed["FRISK_FIXTURE_MODE"] == "probe"
    assert "AWS_SECRET_ACCESS_KEY" not in scrubbed
    assert "OPENAI_API_KEY" not in scrubbed
    assert scrubbed["HOME"] == "/fake"


def test_build_profile_denies_network_and_real_home_secrets():
    profile = build_profile(Path("/tmp/fake"), Path("/Users/real"))
    assert "(deny network*)" in profile
    assert '(deny file-read* (subpath "/Users/real/.ssh"))' in profile
    assert '(deny file-read* (subpath "/Users/real/.aws"))' in profile
    assert '(allow file* (subpath "/tmp/fake"))' in profile
    # The whole home is NOT denied — the interpreter/project under it must still run.
    assert '(deny file* (subpath "/Users/real"))' not in profile


# --- --no-sandbox / disabled + fallback wiring (cross-platform) ------------------------------


def test_disabled_mode_does_not_use_seatbelt(tmp_path):
    target = _probe_target(tmp_path / "r.json", tmp_path / "home")
    result = prepare_stdio(target, SandboxOptions(enabled=False, fake_home=tmp_path / "home"))
    assert result.mode == "disabled"
    assert result.target.command != "sandbox-exec"
    assert result.warning is None


def test_fallback_when_seatbelt_unavailable_warns(tmp_path, monkeypatch):
    monkeypatch.setattr("frisk.sandbox.prepare.seatbelt_available", lambda: False)
    target = _probe_target(tmp_path / "r.json", tmp_path / "home")
    result = prepare_stdio(target, SandboxOptions(enabled=True, fake_home=tmp_path / "home"))
    assert result.mode == "fallback"
    assert result.warning and "seatbelt" in result.warning.lower()  # never a silent downgrade


def test_prepare_forces_fake_home_in_env(tmp_path):
    target = _probe_target(tmp_path / "r.json", tmp_path / "home")
    result = prepare_stdio(target, SandboxOptions(fake_home=tmp_path / "home"))
    assert result.target.env["HOME"] == str(tmp_path / "home")


# --- honeypot decoys are seeded in every mode (R24) ------------------------------------------


def _assert_decoys_seeded(result, fake_home: Path):
    assert result.decoys is not None
    assert result.decoys.home == fake_home
    key = fake_home / ".ssh" / "id_rsa"
    assert key.is_file()
    assert result.decoys.canary in key.read_text(encoding="utf-8")


def test_decoys_seeded_in_default_mode(tmp_path):
    target = _probe_target(tmp_path / "r.json", tmp_path / "home")
    result = prepare_stdio(target, SandboxOptions(fake_home=tmp_path / "home"))
    _assert_decoys_seeded(result, tmp_path / "home")


def test_decoys_seeded_in_disabled_mode(tmp_path):
    target = _probe_target(tmp_path / "r.json", tmp_path / "home")
    result = prepare_stdio(target, SandboxOptions(enabled=False, fake_home=tmp_path / "home"))
    assert result.mode == "disabled"
    _assert_decoys_seeded(result, tmp_path / "home")


def test_decoys_seeded_in_fallback_mode(tmp_path, monkeypatch):
    monkeypatch.setattr("frisk.sandbox.prepare.seatbelt_available", lambda: False)
    target = _probe_target(tmp_path / "r.json", tmp_path / "home")
    result = prepare_stdio(target, SandboxOptions(enabled=True, fake_home=tmp_path / "home"))
    assert result.mode == "fallback"
    _assert_decoys_seeded(result, tmp_path / "home")


# --- seatbelt behavior (macOS only) ---------------------------------------------------------


@requires_seatbelt
def test_seatbelt_blocks_network_but_scan_completes(tmp_path, local_listener):
    host, port = local_listener
    result_file = tmp_path / "probe.json"
    fake_home = tmp_path / "home"
    env = {"FRISK_PROBE_HOST": host, "FRISK_PROBE_PORT": str(port)}
    target = _probe_target(result_file, fake_home, extra_env=env)
    sb = prepare_stdio(target, SandboxOptions(fake_home=fake_home))
    assert sb.mode == "seatbelt"
    # Enumeration still completes despite the server's failed socket attempt (R4).
    inv = enumerate_target(sb.target, timeout=sb.timeout_seconds)
    assert inv.items  # benign tools enumerated
    outcome = json.loads(result_file.read_text())
    assert outcome["network"].startswith("blocked")


@requires_seatbelt
def test_seatbelt_control_unsandboxed_can_reach_listener(tmp_path, local_listener):
    # Control: without the seatbelt layer the same probe connects — proves the block is real.
    host, port = local_listener
    result_file = tmp_path / "probe.json"
    fake_home = tmp_path / "home"
    env = {"FRISK_PROBE_HOST": host, "FRISK_PROBE_PORT": str(port)}
    target = _probe_target(result_file, fake_home, extra_env=env)
    sb = prepare_stdio(target, SandboxOptions(enabled=False, fake_home=fake_home))
    enumerate_target(sb.target, timeout=sb.timeout_seconds)
    outcome = json.loads(result_file.read_text())
    assert outcome["network"] == "connected"


@requires_seatbelt
def test_seatbelt_reads_decoy_home_not_real_key(tmp_path):
    result_file = tmp_path / "probe.json"
    fake_home = tmp_path / "home"
    target = _probe_target(result_file, fake_home)
    sb = prepare_stdio(target, SandboxOptions(fake_home=fake_home))
    enumerate_target(sb.target, timeout=sb.timeout_seconds)
    outcome = json.loads(result_file.read_text())
    assert outcome["home"] == str(fake_home)  # decoy HOME, not the real one
    # M3: the probe reads the seeded DECOY key — canary material, never the user's real key.
    assert sb.decoys.canary in outcome["ssh_key_contents"]
    assert "PRIVATE KEY" in outcome["ssh_key_contents"]  # realistic-shaped decoy


@requires_seatbelt
def test_seatbelt_scrubs_ambient_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("FRISK_SENTINEL_SECRET", "leak-me-if-you-can")
    result_file = tmp_path / "probe.json"
    fake_home = tmp_path / "home"
    target = _probe_target(result_file, fake_home)
    sb = prepare_stdio(target, SandboxOptions(fake_home=fake_home))
    enumerate_target(sb.target, timeout=sb.timeout_seconds)
    outcome = json.loads(result_file.read_text())
    assert outcome["ambient_secret_visible"] is False  # scrubbed (S3)


@requires_seatbelt
def test_hard_timeout_contains_a_hanging_server(tmp_path):
    fake_home = tmp_path / "home"
    target = StdioTarget(
        command=sys.executable,
        args=["-m", "tests.fixtures.mcp_server"],
        env={"FRISK_FIXTURE_MODE": "hang", "PYTHONPATH": REPO_ROOT},
        cwd=REPO_ROOT,
    )
    sb = prepare_stdio(target, SandboxOptions(fake_home=fake_home, timeout_seconds=2.0))
    start = time.monotonic()
    with pytest.raises(ConnectorError):
        enumerate_target(sb.target, timeout=sb.timeout_seconds)
    assert time.monotonic() - start < 15  # the hard timeout fired, not a 1h hang
