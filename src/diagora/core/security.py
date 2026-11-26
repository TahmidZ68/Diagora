"""Filesystem boundary enforcement, symlink containment, resource caps, and secret redaction."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePath, PureWindowsPath
from typing import Any

from diagora.core.exceptions import (
    DiagnosticExecutionError,
    InvalidRepositoryPathError,
    PathSecurityError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
    ResourceLimitExceededError,
)

REDACTED_PLACEHOLDER = "[REDACTED]"
DEFAULT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MiB

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:^|[_.\-])("
    r"secret|password|passwd|pwd|token|api[_.\-]?key|apikey|"
    r"private[_.\-]?key|access[_.\-]?key|secret[_.\-]?key|"
    r"client[_.\-]?secret|client[_.\-]?key|service[_.\-]?key|"
    r"auth[_.\-]?token|bearer|credential|credentials|connection[_.\-]?string|"
    r"database[_.\-]?url|db[_.\-]?password|jwt[_.\-]?secret|signing[_.\-]?key|"
    r"encryption[_.\-]?key|master[_.\-]?key|session[_.\-]?key|csrf[_.\-]?key|"
    r"hmac[_.\-]?key|ssh[_.\-]?key|gpg[_.\-]?key|webhook[_.\-]?key|"
    r"google[_.\-]?key|aws[_.\-]?key|stripe[_.\-]?key|"
    r"openai[_.\-]?key|anthropic[_.\-]?key|github[_.\-]?key"
    r")(?:$|[_.\-])",
    re.IGNORECASE,
)

_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

_URL_CREDENTIALS_PATTERN = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s@]+:)([^@\s/]+)(@)")

_AUTH_HEADER_PATTERN = re.compile(
    r"(?i)(\b(?:x-|proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?(?:basic|bearer)[ \t]+)"
    r"([A-Za-z0-9._~+/\-]{4,}={0,2})"
)

_STANDALONE_BASIC_PATTERN = re.compile(
    r"(?i)\b(basic[ \t]+)([A-Za-z0-9+/_\-]{4,}={0,2})(?=$|[\s\"',;\]})])"
)

_STANDALONE_BEARER_PATTERN = re.compile(
    r"(?i)\b(bearer[ \t]+)([A-Za-z0-9._~+/\-]{12,}=*)(?=$|[\s\"',;\]})])"
)

_TOKEN_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # GitHub personal access tokens and fine-grained tokens
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})\b"),
    # OpenAI / Anthropic / Stripe style sk- keys
    re.compile(r"\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_\-]{16,}\b"),
    # AWS Access Key IDs
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # Google API keys
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35,}\b"),
    # npm and PyPI tokens
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9\-_]{20,}\b"),
    # Slack tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)

_INLINE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:"
    r"SECRET|PASSWORD|PASSWD|TOKEN|APIKEY|"
    r"API_KEY|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY|SIGNING_KEY|"
    r"ENCRYPTION_KEY|MASTER_KEY|SESSION_KEY|CSRF_KEY|HMAC_KEY|"
    r"SSH_KEY|GPG_KEY|WEBHOOK_KEY|CLIENT_KEY|SERVICE_KEY|"
    r"GOOGLE_KEY|AWS_KEY|STRIPE_KEY|OPENAI_KEY|ANTHROPIC_KEY|GITHUB_KEY"
    r")[A-Z0-9_]*)"
    r"(\s*[:=]\s*)"
    r"([\"']?[^\s\"',;]+[\"']?)"
)


def _is_likely_basic_base64(token: str) -> bool:
    """Heuristically identify Base64 Basic credentials without decoding them."""
    if not token:
        return False
    has_padding = token.endswith("=")
    if not has_padding and len(token) % 4 != 0:
        return False
    if len(token) < 4:
        return False
    return (
        has_padding
        or any(ch.isdigit() or ch in "+/_-" for ch in token)
        or any(ch.isupper() for ch in token[1:])
    )


def _is_likely_bearer_token(token: str) -> bool:
    """Identify likely Bearer tokens while avoiding plain English words."""
    return any(ch.isdigit() or ch in "._-+=/~" for ch in token) or any(
        ch.isupper() for ch in token[1:]
    )


def is_sensitive_key(key: str) -> bool:
    """Return True if a mapping or environment variable key indicates sensitive data."""
    normalized = key.strip()
    if not normalized:
        return False
    return bool(_SENSITIVE_KEY_PATTERN.search(normalized))


def redact_secrets(text: str) -> str:
    """Redact credentials, private keys, and high-risk tokens from a string."""
    if not text:
        return text

    redacted = _PEM_PRIVATE_KEY_PATTERN.sub(REDACTED_PLACEHOLDER, text)
    redacted = _URL_CREDENTIALS_PATTERN.sub(rf"\1{REDACTED_PLACEHOLDER}\3", redacted)
    redacted = _AUTH_HEADER_PATTERN.sub(rf"\1{REDACTED_PLACEHOLDER}", redacted)

    def _replace_basic(match: re.Match[str]) -> str:
        prefix, credential = match.group(1), match.group(2)
        if _is_likely_basic_base64(credential):
            return f"{prefix}{REDACTED_PLACEHOLDER}"
        return match.group(0)

    def _replace_bearer(match: re.Match[str]) -> str:
        prefix, credential = match.group(1), match.group(2)
        if _is_likely_bearer_token(credential):
            return f"{prefix}{REDACTED_PLACEHOLDER}"
        return match.group(0)

    redacted = _STANDALONE_BASIC_PATTERN.sub(_replace_basic, redacted)
    redacted = _STANDALONE_BEARER_PATTERN.sub(_replace_bearer, redacted)

    def _replace_assignment(match: re.Match[str]) -> str:
        key_name = match.group(1)
        sep = match.group(2)
        return f"{key_name}{sep}{REDACTED_PLACEHOLDER}"

    redacted = _INLINE_ASSIGNMENT_PATTERN.sub(_replace_assignment, redacted)

    for pattern in _TOKEN_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED_PLACEHOLDER, redacted)

    return redacted


def redact_value(value: Any, *, key_hint: str | None = None) -> Any:
    """Recursively redact sensitive keys and secret patterns in arbitrary data structures."""
    if key_hint is not None and is_sensitive_key(key_hint):
        if value is None or value == "":
            return value
        return REDACTED_PLACEHOLDER

    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(k): redact_value(v, key_hint=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value


def validate_repository_root(path: Path | str) -> Path:
    """Validate and resolve a repository root directory safely.

    Raises:
        InvalidRepositoryPathError: If the path contains null bytes or is not a directory.
        RepositoryNotFoundError: If the path does not exist.
        PathSecurityError: If the root path itself is a symbolic link when symlinks are disallowed.
        RepositoryPermissionError: If the directory cannot be listed due to permissions.
    """
    raw = str(path)
    if "\x00" in raw or not raw.strip():
        raise InvalidRepositoryPathError(
            "Repository path is empty or contains invalid characters.",
            details={"path": raw},
        )

    candidate = Path(raw).expanduser()
    try:
        exists = candidate.exists()
        is_symlink = candidate.is_symlink()
    except PermissionError as exc:
        raise RepositoryPermissionError(
            "Permission denied while accessing repository path.",
            details={"path": raw},
        ) from exc
    except OSError as exc:
        raise InvalidRepositoryPathError(
            f"Invalid repository path: {exc}",
            details={"path": raw},
        ) from exc

    if is_symlink:
        raise PathSecurityError(
            "Symbolic link root paths are not allowed for static scans.",
            details={"path": raw},
        )

    if not exists:
        raise RepositoryNotFoundError(
            f"Repository path does not exist: {raw}",
            details={"path": raw},
        )

    if not candidate.is_dir():
        raise InvalidRepositoryPathError(
            f"Repository path is not a directory: {raw}",
            details={"path": raw},
        )

    try:
        resolved = candidate.resolve(strict=True)
        # Verify directory listing permission upfront
        with os.scandir(resolved) as entries:
            next(entries, None)
    except PermissionError as exc:
        raise RepositoryPermissionError(
            f"Permission denied reading repository directory: {raw}",
            details={"path": raw},
        ) from exc
    except OSError as exc:
        raise DiagnosticExecutionError(
            f"Unable to access repository directory: {exc}",
            details={"path": raw},
        ) from exc

    return resolved


def validate_within_root(
    target_path: Path | str,
    repo_root: Path,
    *,
    follow_symlinks: bool = False,
) -> Path:
    """Ensure `target_path` resolves strictly within `repo_root` without escaping."""
    raw_target = str(target_path)
    if "\x00" in raw_target:
        raise PathSecurityError("Path contains null byte.")

    resolved_root = repo_root.resolve(strict=True)
    candidate = Path(target_path)
    if not candidate.is_absolute():
        candidate = resolved_root / candidate

    # Check lexical normalization before touching filesystem symlinks
    lexical_norm = Path(os.path.normpath(str(candidate)))
    if not lexical_norm.is_relative_to(resolved_root):
        raise PathSecurityError(
            "Path escapes repository boundary via relative traversal.",
            details={"target": raw_target},
        )

    # Walk each segment from resolved_root to lexical_norm to detect intermediate symlinks
    rel_parts = lexical_norm.relative_to(resolved_root).parts
    current = resolved_root
    for part in rel_parts:
        current = current / part
        try:
            if current.is_symlink() and not follow_symlinks:
                raise PathSecurityError(
                    "Symbolic links are not permitted during static scans.",
                    details={"target": "/".join(rel_parts)},
                )
        except PermissionError as exc:
            raise RepositoryPermissionError(
                "Permission denied inspecting path inside repository.",
                details={"target": "/".join(rel_parts)},
            ) from exc

    try:
        resolved_target = lexical_norm.resolve(strict=False)
    except OSError as exc:
        raise PathSecurityError(
            f"Failed to resolve path safely: {exc}",
            details={"target": raw_target},
        ) from exc

    if not resolved_target.is_relative_to(resolved_root):
        raise PathSecurityError(
            "Resolved path escapes the repository root boundary.",
            details={"target": raw_target},
        )

    return resolved_target


def to_relative_posix_path(path: Path | str, repo_root: Path) -> str:
    """Return a clean repository-relative POSIX path without leaking host filesystem paths."""
    validated = validate_within_root(path, repo_root, follow_symlinks=False)
    resolved_root = repo_root.resolve(strict=True)
    rel = validated.relative_to(resolved_root)
    posix_str = rel.as_posix()
    return "." if posix_str == "" else posix_str


def validate_relative_finding_path(file_path: str) -> str:
    """Validate that a finding file path is strictly relative and free of traversal."""
    cleaned = file_path.strip()
    if not cleaned:
        raise ValueError("Finding file path cannot be empty when provided.")
    if "\x00" in cleaned:
        raise ValueError("Finding file path contains null byte.")

    normalized = cleaned.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        raise ValueError(f"Absolute paths are not allowed in findings: {file_path}")

    win_path = PureWindowsPath(cleaned)
    if win_path.drive or win_path.root:
        raise ValueError(
            f"Drive-qualified or rooted paths are not allowed in findings: {file_path}"
        )

    pure = PurePath(normalized)
    if ".." in pure.parts:
        raise ValueError(f"Path traversal segments ('..') are not allowed in findings: {file_path}")

    return pure.as_posix()


def safe_read_text(
    file_path: Path | str,
    repo_root: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    follow_symlinks: bool = False,
) -> str:
    """Safely read a UTF-8 text file within the repository boundary with size enforcement."""
    resolved = validate_within_root(file_path, repo_root, follow_symlinks=follow_symlinks)
    rel_display = resolved.relative_to(repo_root.resolve(strict=True)).as_posix()

    try:
        stat_result = resolved.stat()
    except FileNotFoundError as exc:
        raise DiagnosticExecutionError(
            f"File not found: {rel_display}",
            details={"file": rel_display},
        ) from exc
    except PermissionError as exc:
        raise RepositoryPermissionError(
            f"Permission denied accessing file: {rel_display}",
            details={"file": rel_display},
        ) from exc

    if stat_result.st_size > max_bytes:
        raise ResourceLimitExceededError(
            f"File '{rel_display}' ({stat_result.st_size} bytes) exceeds "
            f"maximum allowed size ({max_bytes} bytes).",
            details={
                "file": rel_display,
                "size_bytes": stat_result.st_size,
                "max_bytes": max_bytes,
            },
        )

    try:
        raw_bytes = resolved.read_bytes()
    except PermissionError as exc:
        raise RepositoryPermissionError(
            f"Permission denied reading file: {rel_display}",
            details={"file": rel_display},
        ) from exc
    except OSError as exc:
        raise DiagnosticExecutionError(
            f"I/O error reading file '{rel_display}': {exc}",
            details={"file": rel_display},
        ) from exc

    if len(raw_bytes) > max_bytes:
        raise ResourceLimitExceededError(
            f"File '{rel_display}' exceeds maximum allowed size ({max_bytes} bytes).",
            details={"file": rel_display, "max_bytes": max_bytes},
        )

    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiagnosticExecutionError(
            f"File '{rel_display}' is not valid UTF-8 text.",
            details={"file": rel_display},
        ) from exc
