"""Runtime interpreter and tool availability probe interface (Phase 3 foundation)."""

from __future__ import annotations

from typing import Protocol


class EnvironmentProbe(Protocol):
    """Protocol for opt-in runtime environment availability probes."""

    def probe_tool_version(self, executable: str) -> str | None:
        """Return the installed version of an allowlisted tool or None if unavailable."""
