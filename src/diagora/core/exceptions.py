"""Structured exception hierarchy and CLI exit codes for Diagora."""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class ExitCode(IntEnum):
    """Standardized CLI exit codes per PRD Section 4."""

    OK = 0
    POLICY_FAILURE = 1
    INVALID_USAGE = 2
    EXECUTION_ERROR = 3
    UNSUPPORTED_SCAN = 4


class DiagoraError(Exception):
    """Base exception for all structured Diagora errors."""

    exit_code: ExitCode = ExitCode.EXECUTION_ERROR
    error_code: str = "DIAGORA_ERROR"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}


class InvalidArgumentError(DiagoraError):
    """Raised when CLI arguments or options are invalid."""

    exit_code = ExitCode.INVALID_USAGE
    error_code = "INVALID_ARGUMENT"


class RepositoryNotFoundError(InvalidArgumentError):
    """Raised when the specified repository path does not exist."""

    error_code = "REPOSITORY_NOT_FOUND"


class InvalidRepositoryPathError(InvalidArgumentError):
    """Raised when the target path is not a valid directory or repository root."""

    error_code = "INVALID_REPOSITORY_PATH"


class DiagnosticExecutionError(DiagoraError):
    """Raised when an internal or environment error prevents scan completion."""

    exit_code = ExitCode.EXECUTION_ERROR
    error_code = "DIAGNOSTIC_EXECUTION_ERROR"


class RepositoryPermissionError(DiagnosticExecutionError):
    """Raised when filesystem permissions prevent reading the repository or output target."""

    error_code = "REPOSITORY_PERMISSION_ERROR"


class PathSecurityError(DiagnosticExecutionError):
    """Raised when a path traversal attempt or disallowed symlink escape is detected."""

    error_code = "PATH_SECURITY_VIOLATION"


class ResourceLimitExceededError(DiagnosticExecutionError):
    """Raised when a file or directory exceeds configured size or recursion limits."""

    error_code = "RESOURCE_LIMIT_EXCEEDED"


class RuleRegistrationError(DiagnosticExecutionError):
    """Raised when a rule definition is duplicate, malformed, or unregistered."""

    error_code = "RULE_REGISTRATION_ERROR"


class AnalyzerRegistrationError(DiagnosticExecutionError):
    """Raised when an analyzer registration fails validation."""

    error_code = "ANALYZER_REGISTRATION_ERROR"


class UnsupportedScanError(DiagoraError):
    """Raised when the requested scan mode or target is unsupported."""

    exit_code = ExitCode.UNSUPPORTED_SCAN
    error_code = "UNSUPPORTED_SCAN"
