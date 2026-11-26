"""Versioned JSON report serializer and safe file output writer."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from diagora import SCHEMA_VERSION, __version__
from diagora.core.exceptions import (
    DiagnosticExecutionError,
    InvalidArgumentError,
    PathSecurityError,
    RepositoryPermissionError,
)
from diagora.core.models import ScanResult
from diagora.core.security import redact_value
from diagora.rules.registry import RuleDefinition


def serialize_scan_result(result: ScanResult, *, indent: int = 2) -> str:
    """Serialize a `ScanResult` to a versioned, secret-redacted JSON string."""
    payload = result.model_dump(mode="json")
    sanitized = redact_value(payload)
    return json.dumps(sanitized, indent=indent, sort_keys=False)


def serialize_rules_json(rules: Sequence[RuleDefinition], *, indent: int = 2) -> str:
    """Serialize a sequence of `RuleDefinition` models into a versioned JSON envelope."""
    implemented_count = sum(1 for r in rules if r.implemented)
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "product_name": "diagora",
        "product_version": __version__,
        "total_rules": len(rules),
        "implemented_rules": implemented_count,
        "deferred_rules": len(rules) - implemented_count,
        "rules": [r.model_dump(mode="json") for r in rules],
    }
    return json.dumps(envelope, indent=indent, sort_keys=False)


def write_report_file(content: str, output_path: Path | str) -> Path:
    """Safely write serialized report content to `output_path`."""
    raw = str(output_path)
    if "\x00" in raw or not raw.strip():
        raise InvalidArgumentError("Output file path cannot be empty or contain null bytes.")

    candidate = Path(raw).expanduser()
    try:
        if candidate.is_symlink():
            raise PathSecurityError(
                f"Refusing to overwrite symbolic link output path: {raw}",
                details={"output_path": raw},
            )
        if candidate.exists() and candidate.is_dir():
            raise InvalidArgumentError(
                f"Output path is an existing directory, expected a file path: {raw}",
                details={"output_path": raw},
            )
        parent = candidate.resolve(strict=False).parent
        parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(content, encoding="utf-8")
        return candidate.resolve(strict=True)
    except (InvalidArgumentError, PathSecurityError):
        raise
    except PermissionError as exc:
        raise RepositoryPermissionError(
            f"Permission denied writing report to '{raw}'.",
            details={"output_path": raw},
        ) from exc
    except OSError as exc:
        raise DiagnosticExecutionError(
            f"Failed to write report to '{raw}': {exc}",
            details={"output_path": raw},
        ) from exc
