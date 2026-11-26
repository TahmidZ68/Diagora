"""Opt-in local port and service reachability probe interface (Phase 3 foundation)."""

from __future__ import annotations

from typing import Protocol


class NetworkProbe(Protocol):
    """Protocol for checking local TCP port availability during opt-in runtime checks."""

    def is_port_free(self, host: str, port: int) -> bool:
        """Return True if the specified local TCP port is available."""
