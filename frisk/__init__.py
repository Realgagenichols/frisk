"""frisk — vet a third-party MCP server before you trust it."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Keyed on the DISTRIBUTION name (`mcp-frisk`), not the import package (`frisk`) —
    # they differ because `frisk` was taken on PyPI, same as its sibling mcp-tollbooth.
    # Read from installed metadata rather than a literal: the JSON report stamps this into
    # `frisk_version`, and a hand-copied constant drifts from pyproject silently — a report
    # that misstates which version produced it is worse than one with no version at all.
    __version__ = version("mcp-frisk")
except PackageNotFoundError:
    # No installed distribution to read. That is the Pyodide playground, where the core is
    # unpacked from a zip rather than pip-installed — and a report stamped "0.0.0+unknown"
    # tells a reader nothing about which detectors produced it. The site build writes the
    # resolved version into the bundle for exactly this case.
    try:
        from frisk._bundled_version import __version__  # type: ignore[no-redef]
    except ImportError:  # a source tree with neither an install nor a bundle
        __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
