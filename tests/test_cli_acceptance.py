"""CLI acceptance tests — drive the INSTALLED `frisk` binary end to end (R17, R18).

Per cross-cutting Pattern 9 these locate the console script via ``sys.prefix`` (not ``-m``)
so they exercise the real entry point the user runs, against the current source.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FRISK_BIN = Path(sys.prefix) / "bin" / "frisk"

pytestmark = pytest.mark.skipif(
    not FRISK_BIN.exists(), reason="frisk console script not installed (run `uv sync`)"
)


def run_frisk(*args, env_extra=None):
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    env.update(env_extra or {})
    return subprocess.run(
        [str(FRISK_BIN), *args],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )


def scan_args(mode, *frisk_opts):
    # frisk's own options come BEFORE the target command; everything after the target is
    # passed through to the child (argparse.REMAINDER).
    return (
        "scan",
        *frisk_opts,
        sys.executable,
        "-m",
        "tests.fixtures.mcp_server",
        "--mode",
        mode,
    )


def verify_args(mode, *frisk_opts):
    return (
        "verify",
        *frisk_opts,
        sys.executable,
        "-m",
        "tests.fixtures.mcp_server",
        "--mode",
        mode,
    )


def test_help_runs():
    result = run_frisk("--help")
    assert result.returncode == 0
    assert "Vet a third-party MCP server" in result.stdout


def test_scan_poisoned_reports_findings_and_exits_2(tmp_path):
    lock = tmp_path / "frisk.lock"
    result = run_frisk(*scan_args("poisoned", "--lock", str(lock)))
    assert result.returncode == 2, result.stderr  # HIGH findings → exit 2 (R18)
    assert "FAIL" in result.stdout
    assert "D1" in result.stdout  # instruction injection fired
    assert lock.exists()  # baseline written (R14)


def test_scan_benign_is_clean_and_exits_0(tmp_path):
    lock = tmp_path / "frisk.lock"
    result = run_frisk(*scan_args("benign", "--lock", str(lock)))
    assert result.returncode == 0, result.stdout + result.stderr  # clean → exit 0
    assert "PASS" in result.stdout


def test_scan_json_format_is_valid_and_machine_readable():
    result = run_frisk(*scan_args("poisoned", "--format", "json", "--no-lock"))
    assert result.returncode == 2
    doc = json.loads(result.stdout)  # parses cleanly
    assert doc["verdict"] == "fail"
    assert any(f["detector"] == "D1" for f in doc["findings"])


def test_verify_detects_rug_pull_and_exits_2(tmp_path):
    lock = tmp_path / "frisk.lock"
    # Lock the benign definitions...
    scan = run_frisk(*scan_args("benign", "--lock", str(lock)))
    assert scan.returncode == 0 and lock.exists(), scan.stderr
    # ...then the server mutates a definition → verify must catch drift and exit non-zero (R14).
    verify = run_frisk(*verify_args("mutated", "--lock", str(lock)))
    assert verify.returncode == 2, verify.stdout + verify.stderr
    assert "DRIFT" in verify.stdout and "mutated" in verify.stdout


def test_verify_unchanged_exits_0(tmp_path):
    lock = tmp_path / "frisk.lock"
    run_frisk(*scan_args("benign", "--lock", str(lock)))
    verify = run_frisk(*verify_args("benign", "--lock", str(lock)))
    assert verify.returncode == 0, verify.stdout + verify.stderr
    assert "OK" in verify.stdout


def test_scan_unreachable_target_fails_loudly_nonzero():
    result = run_frisk("scan", "/nonexistent/frisk-no-such-server", "--no-lock")
    assert result.returncode != 0
    assert "error:" in result.stderr  # specific, actionable — not "0 findings"
