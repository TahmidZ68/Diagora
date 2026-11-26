"""Opt-in Docker CLI and Compose availability probe interface (Phase 3 foundation)."""

from __future__ import annotations

from typing import Protocol


class DockerProbe(Protocol):
    """Protocol for checking local Docker CLI and Compose availability."""

    def is_docker_available(self) -> bool:
        """Return True if the Docker CLI is installed and responsive."""
