"""Remediation plan model and planner interface (Phase 5 foundation)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from diagora.core.security import validate_relative_finding_path


class RemediationStep(BaseModel):
    """A single previewable remediation action scoped to a repository file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(..., min_length=1)
    target_file: str = Field(..., description="Repository-relative file path to modify.")
    description: str = Field(..., min_length=1)
    diff_preview: str = Field(..., description="Unified diff preview of proposed changes.")


def validate_remediation_target(target_file: str) -> str:
    """Ensure remediation target path is strictly repository-relative and free of traversal."""
    return validate_relative_finding_path(target_file)
