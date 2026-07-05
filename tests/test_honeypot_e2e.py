"""End-to-end honeypot behaviour (R24): a real sandboxed child that reads/exfiltrates the
decoy credentials, driven through the same prepare → enumerate → inspect flow the CLI uses."""

import os
import sys

import pytest

from frisk.connector import StdioTarget, enumerate_target
from frisk.core.detectors import ALL_DETECTORS
from frisk.core.engine import run_detectors
from frisk.core.models import Severity
from frisk.core.score import assess, exit_code
from frisk.sandbox import SandboxOptions, inspect_decoys, prepare_stdio, scan_for_canary

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scan(mode: str, tmp_path, *, enabled: bool = True):
    """Mirror cli._enumerate: sandbox+seed, enumerate the child, then run the honeypot and
    fold its findings into the same assessment the CLI produces."""
    target = StdioTarget(
        command=sys.executable,
        args=["-m", "tests.fixtures.mcp_server", "--mode", mode],
        env={"PYTHONPATH": REPO_ROOT},
        cwd=REPO_ROOT,
    )
    sb = prepare_stdio(
        target, SandboxOptions(enabled=enabled, fake_home=tmp_path / f"home-{mode}")
    )
    inventory = enumerate_target(sb.target, timeout=sb.timeout_seconds)
    honeypot = inspect_decoys(sb.decoys) + scan_for_canary(inventory, sb.decoys)
    findings = run_detectors(inventory, ALL_DETECTORS) + honeypot
    return sb, inventory, honeypot, findings, assess(findings)


def _categories(findings):
    return {f.evidence.category for f in findings if f.detector == "D8"}


def test_snoop_server_trips_decoy_access(tmp_path):
    sb, _, honeypot, findings, assessment = _scan("snoop", tmp_path)
    if not sb.decoys.atime_reliable:  # pragma: no cover — dev/CI filesystems have atime
        pytest.skip("filesystem does not support atime-based access detection")
    access = [f for f in honeypot if f.evidence.category == "decoy-access"]
    assert any(f.item_ref == "honeypot:.ssh/id_rsa" for f in access)
    assert all(f.severity == Severity.HIGH for f in access)
    assert exit_code(assessment) == 2  # HIGH → fail (R18)


def test_thief_server_trips_canary_exfiltration(tmp_path):
    sb, inventory, honeypot, findings, assessment = _scan("thief", tmp_path)
    exfil = [f for f in honeypot if f.evidence.category == "canary-exfiltration"]
    assert exfil, "the stolen AWS canary must be caught in the advertised definitions"
    assert exfil[0].severity == Severity.CRITICAL
    assert assessment.verdict == "fail"
    assert exit_code(assessment) == 2  # CRITICAL → fail (R18)
    # S3: the exfiltrated canary value never surfaces in any finding's message/evidence.
    assert all(sb.decoys.canary not in f.message for f in findings)
    assert all(f.evidence.snippet is None for f in honeypot)


def test_benign_twin_produces_no_honeypot_findings(tmp_path):
    """N2: the honest server (plus Python interpreter startup noise) touches no decoy."""
    _, _, honeypot, findings, assessment = _scan("benign", tmp_path)
    assert honeypot == []
    assert _categories(findings) == set()
    assert exit_code(assessment) == 0  # unchanged from M2 — honeypot adds nothing when clean


def test_thief_detected_without_sandbox(tmp_path):
    """R24: the honeypot seeds and detects even in --no-sandbox (disabled) mode."""
    sb, _, honeypot, _, assessment = _scan("thief", tmp_path, enabled=False)
    assert sb.mode == "disabled"
    assert any(f.evidence.category == "canary-exfiltration" for f in honeypot)
    assert exit_code(assessment) == 2
