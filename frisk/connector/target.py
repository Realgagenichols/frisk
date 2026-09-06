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
    # What to call this target in errors. The sandbox rewrites `command` to `sandbox-exec`,
    # so without this every failure read `stdio:sandbox-exec` — naming frisk's own wrapper
    # instead of the command the user typed, which is the one thing they need to see.
    display_name: str | None = None

    @property
    def label(self) -> str:
        return f"stdio:{self.display_name or self.command}"


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
        """scheme://host[:port] only — never a path, query, or userinfo.

        A URL can carry credentials in three places: the query string (`?api_key=…`), the
        path, and the userinfo component (`https://user:secret@host/`). `netloc` INCLUDES
        userinfo, so labelling with it leaked the password into every error line; `hostname`
        does not (S3, cross-cutting Pattern 11).
        """
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:  # malformed port — drop it rather than echo the raw netloc
            port = None
        suffix = f":{port}" if port else ""
        return f"remote:{parts.scheme}://{host}{suffix}"


Target = StdioTarget | RemoteTarget
