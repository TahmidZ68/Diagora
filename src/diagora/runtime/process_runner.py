"""Safe subprocess execution interface with explicit executable allowlisting."""

from __future__ import annotations

from dataclasses import dataclass

from diagora.core.exceptions import PathSecurityError

ALLOWED_RUNTIME_EXECUTABLES: frozenset[str] = frozenset(
    {
        "python",
        "python3",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "docker",
    }
)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Result of an allowlisted runtime probe command."""

    executable: str
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def validate_allowed_executable(executable: str) -> str:
    """Verify that `executable` is in the strict runtime probe allowlist."""
    cleaned = executable.strip().lower()
    if cleaned not in ALLOWED_RUNTIME_EXECUTABLES:
        raise PathSecurityError(
            f"Executable '{executable}' is not permitted by the runtime security policy.",
            details={"executable": executable},
        )
    return cleaned
