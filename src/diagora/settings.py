"""Application settings and scan configuration for Diagora."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from diagora.core.models import Severity
from diagora.core.security import DEFAULT_MAX_FILE_SIZE_BYTES

DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".turbo",
        "coverage",
        "htmlcov",
    }
)


class ScanSettings(BaseSettings):
    """Runtime and static scan settings configurable via CLI flags or `DIAGORA_*` env vars."""

    model_config = SettingsConfigDict(
        env_prefix="DIAGORA_",
        extra="forbid",
        frozen=True,
    )

    max_file_size_bytes: int = Field(
        default=DEFAULT_MAX_FILE_SIZE_BYTES,
        ge=1024,
        le=100 * 1024 * 1024,
        description="Maximum size in bytes for any single inspected configuration file.",
    )
    max_scan_depth: int = Field(
        default=15,
        ge=1,
        le=50,
        description="Maximum directory recursion depth from the repository root.",
    )
    max_files_scanned: int = Field(
        default=10_000,
        ge=10,
        le=500_000,
        description="Maximum number of repository files visited during discovery.",
    )
    follow_symlinks: bool = Field(
        default=False,
        description="Whether to follow symbolic links that remain within the repository root.",
    )
    enable_runtime_probes: bool = Field(
        default=False,
        description="Enable optional local runtime environment probes.",
    )
    enable_ai_adapter: bool = Field(
        default=False,
        description="Enable optional AI root-cause explanation adapter.",
    )
    min_report_severity: Severity = Field(
        default=Severity.INFORMATIONAL,
        description="Minimum severity level included in output reports.",
    )
    fail_on_severity: Severity | None = Field(
        default=None,
        description="If set, exit with code 1 when any finding meets or exceeds this severity.",
    )
    ignored_directories: frozenset[str] = Field(
        default=DEFAULT_IGNORED_DIRS,
        description="Directory names skipped during repository traversal.",
    )
