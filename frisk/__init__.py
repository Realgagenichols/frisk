"""frisk — vet a third-party MCP server before you trust it."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Read from installed metadata rather than a literal: the JSON report stamps this into
    # `frisk_version`, and a hand-copied constant drifts from pyproject silently — a report
    # that misstates which version produced it is worse than one with no version at all.
    __version__ = version("frisk")
except PackageNotFoundError:  # running from a source tree with no install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
