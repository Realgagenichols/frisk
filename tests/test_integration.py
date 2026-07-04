"""End-to-end integration through the internal API (R1-R18 pipeline) + determinism (N1)."""

import os
import sys

from frisk.connector import StdioTarget, enumerate_target
from frisk.core.detectors import ALL_DETECTORS
from frisk.core.engine import run_detectors
from frisk.core.score import assess, exit_code
from frisk.lockfile import diff_lock, read_lock, write_lock
from frisk.sandbox import SandboxOptions, prepare_stdio

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scan(mode: str, tmp_path):
    """Full sandboxed pipeline: prepare → enumerate → detect → assess."""
    target = StdioTarget(
        command=sys.executable,
        args=["-m", "tests.fixtures.mcp_server", "--mode", mode],
        env={"PYTHONPATH": REPO_ROOT},
        cwd=REPO_ROOT,
    )
    sb = prepare_stdio(target, SandboxOptions(fake_home=tmp_path / f"home-{mode}"))
    inventory = enumerate_target(sb.target, timeout=sb.timeout_seconds)
    findings = run_detectors(inventory, ALL_DETECTORS)
    return inventory, findings, assess(findings)


def test_poisoned_pipeline_fails(tmp_path):
    _, findings, assessment = _scan("poisoned", tmp_path)
    assert assessment.verdict == "fail"
    assert exit_code(assessment) == 2
    assert {f.detector for f in findings} >= {"D1", "D2", "D3", "D4", "D5"}


def test_benign_pipeline_passes(tmp_path):
    _, _, assessment = _scan("benign", tmp_path)
    assert assessment.verdict == "pass"
    assert exit_code(assessment) == 0


def test_scan_then_verify_catches_mutation(tmp_path):
    inv_benign, _, _ = _scan("benign", tmp_path)
    lock = tmp_path / "frisk.lock"
    write_lock(lock, inv_benign)

    inv_mutated, _, _ = _scan("mutated", tmp_path)
    diff = diff_lock(read_lock(lock), inv_mutated)
    assert diff.mutated  # rug pull caught (R14)


def test_detectors_are_deterministic(tmp_path):
    # N1: no network/LLM/randomness — identical inventory → identical findings, run to run.
    inventory, _, _ = _scan("poisoned", tmp_path)
    run_a = run_detectors(inventory, ALL_DETECTORS)
    run_b = run_detectors(inventory, ALL_DETECTORS)
    key = lambda fs: [  # noqa: E731
        (f.detector, f.severity, f.item_ref, f.field, f.evidence.span) for f in fs
    ]
    assert key(run_a) == key(run_b)
