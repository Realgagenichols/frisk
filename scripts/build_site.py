"""Bundle the detector core for the playground (R20, R23).

Zips ``frisk/__init__.py`` + ``frisk/core/**/*.py`` straight from the repo source tree into
``site/dist/frisk_core.zip`` for Pyodide's ``unpackArchive``. The bundle is always generated
from source — the site never carries a second, hand-maintained copy of detector code (R23).
Zip entries get a fixed timestamp so identical source yields a byte-identical bundle.
"""

from __future__ import annotations

import re
import zipfile
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "site" / "dist" / "frisk_core.zip"


def source_files() -> Iterator[Path]:
    yield REPO / "frisk" / "__init__.py"
    for path in sorted((REPO / "frisk" / "core").rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield path


def project_version() -> str:
    """The version from pyproject, read as text rather than imported.

    `frisk.__version__` resolves through installed package metadata, which does not exist in
    the browser — the core is unpacked from this zip, not pip-installed — so without this the
    playground stamped every report `0.0.0+unknown`. Parsed from the source of truth so the
    site cannot disagree with the wheel about which version produced a report.
    """
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("could not find a version in pyproject.toml")
    return match.group(1)


def build(out: Path = DEFAULT_OUT) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w") as zf:
        for path in source_files():
            info = zipfile.ZipInfo(
                path.relative_to(REPO).as_posix(), date_time=(2020, 1, 1, 0, 0, 0)
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes())
        stamp = zipfile.ZipInfo("frisk/_bundled_version.py", date_time=(2020, 1, 1, 0, 0, 0))
        stamp.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(stamp, f'__version__ = "{project_version()}"\n'.encode())
    return out


if __name__ == "__main__":
    built = build()
    print(f"wrote {built.relative_to(Path.cwd()) if built.is_relative_to(Path.cwd()) else built}")
