"""Core Pydantic v2 data models for Diagora findings, issues, rules, and scan results."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from diagora import SCHEMA_VERSION, __version__
from diagora.core.security import (
    redact_secrets,
    redact_value,
    validate_relative_finding_path,
)

_RULE_ID_REGEX = re.compile(r"^[A-Z]{2,4}[0-9]{3}$")


class Severity(str, Enum):
    """Impact-based diagnostic severity levels (distinct from confidence)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        """Numeric rank for ordering and threshold comparisons."""
        ranks: dict[Severity, int] = {
            Severity.CRITICAL: 50,
            Severity.HIGH: 40,
            Severity.MEDIUM: 30,
            Severity.LOW: 20,
            Severity.INFORMATIONAL: 10,
        }
        return ranks[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        """Return True if this severity is greater than or equal to `threshold`."""
        return self.rank >= threshold.rank


class Confidence(str, Enum):
    """Evidence strength level for findings and root-cause hypotheses."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Numeric rank for ordering confidence levels."""
        ranks: dict[Confidence, int] = {
            Confidence.CONFIRMED: 40,
            Confidence.HIGH: 30,
            Confidence.MEDIUM: 20,
            Confidence.LOW: 10,
        }
        return ranks[self]


class Category(str, Enum):
    """Diagnostic domain categories."""

    PYTHON = "python"
    NODE = "node"
    ENVIRONMENT = "environment"
    DOCKER = "docker"
    CONFIGURATION = "configuration"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    REPOSITORY = "repository"


class FindingStatus(str, Enum):
    """Lifecycle status of an individual finding."""

    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    VERIFIED = "verified"


class VerificationState(str, Enum):
    """Post-fix or runtime verification state."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class Ecosystem(str, Enum):
    """Supported repository ecosystems discovered during project classification."""

    PYTHON = "python"
    NODE = "node"
    DOCKER = "docker"
    GITHUB_ACTIONS = "github_actions"
    VERCEL = "vercel"
    GENERIC_DEPLOYMENT = "generic_deployment"


class Evidence(BaseModel):
    """Deterministic evidence backing a diagnostic finding.

    All fields are automatically scrubbed for secrets upon instantiation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed: Any = Field(..., description="Observed state or value in the repository.")
    expected: Any = Field(..., description="Expected state or constraint.")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context supporting the finding.",
    )

    @model_validator(mode="after")
    def _sanitize_evidence(self) -> Evidence:
        object.__setattr__(self, "observed", redact_value(self.observed))
        object.__setattr__(self, "expected", redact_value(self.expected))
        object.__setattr__(self, "details", redact_value(self.details))
        return self


class Finding(BaseModel):
    """Normalized diagnostic finding produced by an analyzer rule."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, description="Unique finding identifier within the scan.")
    rule_id: str = Field(..., description="Stable registered rule ID (e.g., DK001, PY001).")
    title: str = Field(..., min_length=1, description="Concise summary of the finding.")
    description: str = Field(..., min_length=1, description="Detailed explanation of the problem.")
    severity: Severity = Field(..., description="Impact severity of the finding.")
    confidence: Confidence = Field(..., description="Confidence level of the detection.")
    category: Category = Field(..., description="Diagnostic domain category.")
    file: str | None = Field(
        default=None,
        description="Repository-relative POSIX file path where the finding was observed.",
    )
    line: int | None = Field(
        default=None,
        ge=1,
        description="1-based line number in the file where available.",
    )
    evidence: Evidence = Field(..., description="Structured observed vs. expected evidence.")
    recommendation: str = Field(
        ...,
        min_length=1,
        description="Actionable remediation recommendation.",
    )
    related_findings: list[str] = Field(
        default_factory=list,
        description="Identifiers of correlated findings.",
    )
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Remediation lifecycle status of the finding.",
    )

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not _RULE_ID_REGEX.match(cleaned):
            raise ValueError(
                f"Invalid rule_id '{value}'. Expected 2-4 uppercase letters "
                "followed by 3 digits (e.g., PY001)."
            )
        return cleaned

    @field_validator("file")
    @classmethod
    def _validate_file_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_relative_finding_path(value)

    @model_validator(mode="after")
    def _redact_text_fields(self) -> Finding:
        self.title = redact_secrets(self.title)
        self.description = redact_secrets(self.description)
        self.recommendation = redact_secrets(self.recommendation)
        return self


class DiagnosticIssue(BaseModel):
    """Root-cause group correlating one or more related diagnostic findings."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, description="Unique issue identifier (e.g., issue-001).")
    title: str = Field(..., min_length=1, description="Short title of the correlated issue.")
    root_cause_hypothesis: str = Field(
        ...,
        min_length=1,
        description="Explanation of the underlying root cause connecting the findings.",
    )
    related_finding_ids: list[str] = Field(
        ...,
        min_length=1,
        description="Identifiers of the constituent findings.",
    )
    supporting_evidence: list[str] = Field(
        default_factory=list,
        description="Human-readable evidence statements supporting the hypothesis.",
    )
    severity: Severity = Field(..., description="Aggregate severity of the diagnostic issue.")
    confidence: Confidence = Field(..., description="Confidence in the root-cause hypothesis.")
    suggested_next_action: str = Field(
        ...,
        min_length=1,
        description="Primary recommended remediation step to resolve the root cause.",
    )
    verification_state: VerificationState = Field(
        default=VerificationState.UNVERIFIED,
        description="Verification status of the issue.",
    )

    @model_validator(mode="after")
    def _redact_issue_fields(self) -> DiagnosticIssue:
        self.title = redact_secrets(self.title)
        self.root_cause_hypothesis = redact_secrets(self.root_cause_hypothesis)
        self.supporting_evidence = [redact_secrets(item) for item in self.supporting_evidence]
        self.suggested_next_action = redact_secrets(self.suggested_next_action)
        return self


class SubprojectInfo(BaseModel):
    """Metadata for a discovered root or monorepo subproject."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Repository-relative POSIX path to the subproject.")
    ecosystems: list[Ecosystem] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    config_files: list[str] = Field(default_factory=list)
    is_workspace_package: bool = Field(default=False)


class RepositoryContext(BaseModel):
    """Structured inventory of a discovered repository."""

    model_config = ConfigDict(extra="forbid")

    repository_name: str = Field(..., min_length=1)
    relative_path: str = Field(default=".")
    is_git_repository: bool = Field(default=False)
    is_monorepo: bool = Field(default=False)
    is_empty: bool = Field(default=False)
    detected_ecosystems: list[Ecosystem] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    configuration_files: list[str] = Field(default_factory=list)
    docker_files: list[str] = Field(default_factory=list)
    ci_workflows: list[str] = Field(default_factory=list)
    deployment_manifests: list[str] = Field(default_factory=list)
    unsupported_files: list[str] = Field(default_factory=list)
    subprojects: list[SubprojectInfo] = Field(default_factory=list)
    discovered_files: list[str] = Field(default_factory=list)
    total_files_inspected: int = Field(default=0, ge=0)


class ScanSummary(BaseModel):
    """Aggregated counts and policy evaluation status for a scan."""

    model_config = ConfigDict(extra="forbid")

    total_findings: int = Field(default=0, ge=0)
    total_issues: int = Field(default=0, ge=0)
    by_severity: dict[str, int] = Field(default_factory=lambda: {s.value: 0 for s in Severity})
    analyzers_executed: list[str] = Field(
        default_factory=list,
        description="Names of analyzers that executed during the scan.",
    )
    policy_passed: bool = Field(
        default=True,
        description="True if no findings breached the configured severity threshold.",
    )
    execution_status: str = Field(
        default="completed",
        description=(
            "Scan execution status "
            "('completed', 'no_applicable_analyzers', 'partial', or 'failed')."
        ),
    )


class ScanResult(BaseModel):
    """Versioned top-level diagnostic output envelope."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION)
    product_name: str = Field(default="diagora")
    product_version: str = Field(default=__version__)
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    repository: RepositoryContext
    findings: list[Finding] = Field(default_factory=list)
    issues: list[DiagnosticIssue] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    runtime_enabled: bool = Field(default=False)
    verification_status: VerificationState = Field(default=VerificationState.NOT_APPLICABLE)
    warnings: list[str] = Field(default_factory=list)
