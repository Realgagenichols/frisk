"""Site-bundle tests: the generated Pyodide bundle runs the full pipeline with every
browser-unavailable dependency blocked (R20, R23)."""

import json
import subprocess
import sys
import zipfile
from pathlib import Path

from scripts.build_site import build
from tests.fixtures.definitions import D7_BENIGN_SERVER_INFO, POISONED_TOOLS

REPO = Path(__file__).resolve().parent.parent

# Runs the exact pipeline the playground runs, with mcp/anyio/pydantic/HTTP imports blocked
# the way they are absent under Pyodide (recreates the M2 de-risk harness as a regression
# test). Asserts the code actually loaded from the unpacked bundle, not from an installed
# frisk wheel on sys.path (cross-cutting Pattern 9).
CHILD = """
import sys

BLOCKED = {"mcp", "anyio", "pydantic", "httpx", "httpcore", "sniffio", "h11"}


class Blocker:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError(f"blocked browser-unavailable module: {name}")


sys.meta_path.insert(0, Blocker())
bundle_dir = sys.argv[1]
sys.path.insert(0, bundle_dir)

import frisk.core  # noqa: E402

import os  # noqa: E402

assert frisk.core.__file__.startswith(bundle_dir + os.sep), frisk.core.__file__

from frisk.core.engine import run_detectors  # noqa: E402
from frisk.core.ingest import inventory_from_json  # noqa: E402
from frisk.core.report import render_json  # noqa: E402
from frisk.core.score import assess  # noqa: E402

inventory = inventory_from_json(sys.stdin.read())
findings = run_detectors(inventory)
print(render_json(inventory, findings, assess(findings)))
"""


def test_bundle_contains_only_core_sources(tmp_path):
    out = build(tmp_path / "frisk_core.zip")
    names = zipfile.ZipFile(out).namelist()
    assert "frisk/__init__.py" in names
    assert "frisk/core/ingest.py" in names
    assert "frisk/core/detectors/d1_injection.py" in names
    # Nothing browser-hostile sneaks in: no connector/sandbox/cli, no bytecode.
    assert all(n.startswith("frisk/") and n.endswith(".py") for n in names)
    assert not any("/connector/" in n or "/sandbox/" in n or n.endswith("cli.py") for n in names)


def test_bundle_is_deterministic(tmp_path):
    a = build(tmp_path / "a.zip").read_bytes()
    b = build(tmp_path / "b.zip").read_bytes()
    assert a == b


def test_bundle_tracks_source_tree(tmp_path):
    # R23 drift guard: the BUILT ARTIFACT contains exactly the core tree — checked against
    # the zip's own manifest, not against source_files() (which build() also uses).
    names = set(zipfile.ZipFile(build(tmp_path / "frisk_core.zip")).namelist())
    on_disk = {
        p.relative_to(REPO).as_posix()
        for p in (REPO / "frisk" / "core").rglob("*.py")
        if "__pycache__" not in p.parts
    }
    assert names == on_disk | {"frisk/__init__.py"}


def test_bundle_runs_pipeline_with_browser_unavailable_deps_blocked(tmp_path):
    out = build(tmp_path / "frisk_core.zip")
    bundle_dir = tmp_path / "unpacked"
    zipfile.ZipFile(out).extractall(bundle_dir)

    pasted = json.dumps({"tools": POISONED_TOOLS, "serverInfo": dict(D7_BENIGN_SERVER_INFO)})
    proc = subprocess.run(
        [sys.executable, "-c", CHILD, str(bundle_dir)],
        input=pasted,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,  # not the repo: imports must resolve from the bundle alone
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["verdict"] == "fail"
    detectors = {f["detector"] for f in report["findings"]}
    assert {"D1", "D2", "D3", "D4", "D5"} <= detectors
