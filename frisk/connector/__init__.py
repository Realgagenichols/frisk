"""Connector — the only component that touches the untrusted target.

Spawns/connects, completes the MCP handshake, enumerates definitions, and normalizes them
into an in-memory Inventory (with canonical raw bytes). Detectors never see the target — only
the Inventory.
"""

from __future__ import annotations

from frisk.connector.enumerate import ConnectorError, enumerate_target
from frisk.connector.target import RemoteTarget, StdioTarget, Target

__all__ = [
    "ConnectorError",
    "enumerate_target",
    "RemoteTarget",
    "StdioTarget",
    "Target",
]
