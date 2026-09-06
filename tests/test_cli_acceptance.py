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


def test_scan_thief_reports_canary_exfil_in_json_without_leaking_decoy(tmp_path):
    # The thief server steals the decoy AWS credentials and smuggles them into a tool
    # description; the honeypot must catch the exfiltration and gate the exit code (R24, R18).
    result = run_frisk(*scan_args("thief", "--format", "json", "--no-lock"))
    assert result.returncode == 2, result.stderr
    doc = json.loads(result.stdout)
    assert any(
        f["detector"] == "D8" and f["evidence"]["category"] == "canary-exfiltration"
        for f in doc["findings"]
    )
    # S3: the decoy private-key body and PEM markers never appear in the rendered report.
    assert "PRIVATE KEY" not in result.stdout
    assert "aws_secret_access_key" not in result.stdout


def test_verify_snoop_exits_2_even_with_clean_diff(tmp_path):
    """R24: the definitions are unchanged, but the server read a decoy — verify must fail.

    The skip is gated on the CAPABILITY, probed before the run, not on the outcome. It used
    to read `if verify.returncode == 0 and "OK" in stdout: skip(...)` — which is the exact
    symptom of the regression it exists to catch, so deleting the HIGH-severity gate in
    cli.py turned this test green-with-a-skip instead of red (cross-cutting P87).
    """
    from frisk.sandbox import seed_decoys

    if not seed_decoys(tmp_path / "atime-probe").atime_reliable:
        pytest.skip("filesystem does not update atime on read — decoy-access is undetectable")

    lock = tmp_path / "frisk.lock"
    scan = run_frisk(*scan_args("benign", "--lock", str(lock)))
    assert scan.returncode == 0 and lock.exists(), scan.stderr
    verify = run_frisk(*verify_args("snoop", "--lock", str(lock)))
    assert verify.returncode == 2, verify.stdout + verify.stderr
    assert "honeypot:" in verify.stderr and "decoy-access" not in verify.stdout


def test_scan_unreachable_target_fails_loudly_nonzero():
    result = run_frisk("scan", "/nonexistent/frisk-no-such-server", "--no-lock")
    assert result.returncode != 0
    assert "error:" in result.stderr  # specific, actionable — not "0 findings"


def test_scan_unwritable_lock_warns_but_keeps_verdict(tmp_path):
    # A failed baseline write must not mask the risk verdict/exit code, and must not crash.
    unwritable = tmp_path / "nonexistent-dir" / "frisk.lock"
    result = run_frisk(*scan_args("poisoned", "--lock", str(unwritable)))
    assert result.returncode == 2  # verdict preserved
    assert "could not write lockfile" in result.stderr
    assert "Traceback" not in result.stderr  # degraded gracefully


def test_verify_catches_a_rug_pull_hidden_behind_a_duplicate_name(tmp_path):
    """R14/R28 end to end: a poisoned twin swapped in under an existing name.

    The baseline holds two definitions called `search_docs`. The server then poisons the
    FIRST of them and leaves the count and the second twin alone. A lockfile keyed by ref in
    a dict kept only the last line, so this diffed clean and verify exited 0.
    """
    lock = tmp_path / "frisk.lock"
    scan = run_frisk(*scan_args("twins", "--lock", str(lock)))
    assert scan.returncode in (0, 1), scan.stdout + scan.stderr
    twin_lines = [ln for ln in lock.read_text().splitlines() if ln.endswith("tool:read_notes")]
    assert len(twin_lines) == 2, "a duplicate definition was dropped from the baseline"
    assert twin_lines[0] != twin_lines[1], "the twins should hash differently"

    verified = run_frisk(*verify_args("twins-swapped", "--lock", str(lock)))
    assert verified.returncode == 2, verified.stdout + verified.stderr
    assert "mutated" in verified.stdout
    assert "DRIFT" in verified.stdout


def test_scan_flags_duplicate_definition_names(tmp_path):
    result = run_frisk(*scan_args("twins", "--lock", str(tmp_path / "frisk.lock")))
    assert "D5" in result.stdout
    assert "same name" in result.stdout


def test_verify_unchanged_twins_is_not_drift(tmp_path):
    # P21: the duplicate-aware diff must not report drift merely because a name repeats.
    lock = tmp_path / "frisk.lock"
    run_frisk(*scan_args("twins", "--lock", str(lock)))
    verified = run_frisk(*verify_args("twins", "--lock", str(lock)))
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "OK" in verified.stdout


def test_frisk_flag_after_the_target_is_refused_not_swallowed(tmp_path):
    """argparse.REMAINDER hands everything after the target to the child, so
    `frisk scan srv --format json` used to emit a HUMAN report with exit 0/2 and no
    complaint — a CI job parsing that JSON gets prose instead of an error."""
    result = run_frisk(
        "scan",
        sys.executable,
        "-m",
        "tests.fixtures.mcp_server",
        "--mode",
        "benign",
        "--format",
        "json",
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "came after the target" in result.stderr
    assert "--format" in result.stderr
    assert not result.stdout.strip().startswith("{")


def test_server_args_that_are_not_frisk_flags_still_pass_through(tmp_path):
    # P21: the guard must reject OUR flags only — `--mode` belongs to the fixture server and
    # every other test here depends on it reaching the child.
    result = run_frisk(*scan_args("benign", "--lock", str(tmp_path / "frisk.lock")))
    assert result.returncode == 0, result.stdout + result.stderr


def test_unexpected_failure_exits_2_not_1(tmp_path, monkeypatch):
    """Exit 1 means "warnings" in the R18 contract, and an uncaught exception exits 1 —
    so a crash would read to CI as a soft pass."""
    from frisk import cli

    monkeypatch.setattr(cli, "_cmd_scan", lambda args: 1 / 0)
    code = cli.main(["scan", "/bin/true"])
    assert code == 2


def test_plaintext_http_with_a_token_warns(monkeypatch, capsys):
    from frisk import cli

    monkeypatch.setenv("FRISK_AUTH_TOKEN", "s3cr3t")
    parser = cli.build_parser()
    args = parser.parse_args(["scan", "http://insecure.example.com/mcp"])
    cli._build_target(args)
    err = capsys.readouterr().err
    assert "plaintext http://" in err
    assert "s3cr3t" not in err  # the warning names the env var, never the value (S3)


def test_double_dash_lets_a_colliding_flag_reach_the_server(tmp_path):
    result = run_frisk(
        "scan",
        "--lock",
        str(tmp_path / "frisk.lock"),
        sys.executable,
        "-m",
        "tests.fixtures.mcp_server",
        "--mode",
        "benign",
        "--",
        "--timeout",
        "ignored-by-the-fixture",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_relocated_payload_is_caught_through_the_real_connector(tmp_path):
    """Field coverage end to end, not in-process.

    `tool_item()` tests prove the leaf walk; they do not prove that `annotations` survives
    the connector's `model_dump` into `Item.payload`. This drives the real binary against a
    server that puts its payload in `annotations.title` and nowhere else.
    """
    result = run_frisk(*scan_args("relocated", "--format", "json", "--no-lock"))
    assert result.returncode == 2, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert doc["verdict"] == "fail"
    assert any(
        f["detector"] == "D1" and f["field"].startswith("annotations") for f in doc["findings"]
    ), [f["field"] for f in doc["findings"]]


@pytest.mark.parametrize("mode", ["poisoned", "thief", "benign"])
def test_readme_transcript_headers_match_real_output(mode):
    """README:38 claims its transcripts are 'real frisk output, reproducible from a fresh
    clone'. That is a published figure, so it needs a mechanical relation to its source
    (Pattern 68) — adding one resource to the fixture server silently falsified three of
    them. Only the header line is compared: it carries the counts, verdict and score, and
    unlike the finding list it does not churn on every rule tweak.
    """
    result = run_frisk(*scan_args(mode, "--no-lock"))
    header = result.stdout.splitlines()[0]
    verdict_line = result.stdout.splitlines()[1]
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert header in readme, f"README does not contain the current header for {mode}: {header}"
    assert verdict_line in readme, (
        f"README does not contain the current verdict line for {mode}: {verdict_line}"
    )


def test_installed_console_script_runs_without_pythonpath():
    """The other tests inject PYTHONPATH so the fixture SERVER can be imported — which also
    masks a broken install of frisk itself. This one runs the console script with PYTHONPATH
    removed, so it exercises what a user actually gets.

    Known failure mode on macOS: `uv` marks the editable `.pth` in site-packages with
    UF_HIDDEN, and CPython's `site.addpackage` skips hidden `.pth` files, so the editable
    install silently never lands on sys.path. Fix:
        chflags nohidden .venv/lib/python*/site-packages/*.pth
    and use `uv run --no-sync frisk …` (a plain `uv run` re-hides it).
    """
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [str(FRISK_BIN), "--version"], env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"the installed console script is broken: {result.stderr.strip()}\n"
        "See this test's docstring for the macOS UF_HIDDEN .pth cause and fix."
    )
    assert result.stdout.startswith("frisk "), result.stdout


def test_reported_version_matches_installed_metadata():
    # `frisk_version` in the JSON report used to be a hand-copied literal that could drift
    # from pyproject with nothing noticing.
    from importlib.metadata import version

    result = run_frisk(*scan_args("benign", "--format", "json", "--no-lock"))
    assert json.loads(result.stdout)["frisk_version"] == version("mcp-frisk")
