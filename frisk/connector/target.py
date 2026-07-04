"""Target descriptors: what to connect to and how."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StdioTarget:
    """A local stdio MCP server: a command to spawn (R1)."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None

    @property
    def label(self) -> str:
        return f"stdio:{self.command}"


@dataclass(frozen=True)
class RemoteTarget:
    """A remote MCP server reachable by URL (R3).

    ``auth_token`` is ``repr=False`` so it never leaks through a stack trace, log line, or
    debugger dump (S3, cross-cutting Pattern 11). It is only ever placed in an Authorization
    header at connection time.
    """

    url: str
    auth_token: str | None = field(default=None, repr=False)
    transport: str = "auto"  # "auto" | "http" | "sse"

    @property
    def label(self) -> str:
        # The URL may itself carry a token in a query string — show only scheme://host.
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        return f"remote:{parts.scheme}://{parts.netloc}"


Target = StdioTarget | RemoteTarget
