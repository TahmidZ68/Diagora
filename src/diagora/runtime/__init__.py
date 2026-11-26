"""Opt-in runtime diagnostic probes package."""

from __future__ import annotations

from diagora.runtime.process_runner import (
    ALLOWED_RUNTIME_EXECUTABLES,
    ProcessResult,
    validate_allowed_executable,
)

__all__ = [
    "ALLOWED_RUNTIME_EXECUTABLES",
    "ProcessResult",
    "validate_allowed_executable",
]
