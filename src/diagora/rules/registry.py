"""Rule definition model and central rule registry for Diagora."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagora.core.exceptions import RuleRegistrationError
from diagora.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    RepositoryContext,
    Severity,
)

_RULE_ID_REGEX = re.compile(r"^[A-Z]{2,4}[0-9]{3}$")

DetectionFunction = Callable[[Path, RepositoryContext], Sequence[Finding]]


class RuleDefinition(BaseModel):
    """Specification and metadata for a deterministic diagnostic rule."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    rule_id: str = Field(..., description="Stable rule identifier (e.g., PY001, DK001).")
    version: str = Field(default="1.0.0", min_length=1, description="Semantic version of the rule.")
    name: str = Field(..., min_length=1, description="Short human-readable name.")
    description: str = Field(
        ..., min_length=1, description="Detailed explanation of what the rule checks."
    )
    category: Category = Field(..., description="Diagnostic domain category.")
    default_severity: Severity = Field(..., description="Default impact severity.")
    evidence_requirements: list[str] = Field(
        default_factory=lambda: ["observed", "expected"],
        min_length=1,
        description="Required evidence fields for findings produced by this rule.",
    )
    remediation_guidance: str = Field(
        ...,
        min_length=1,
        description="Actionable remediation guidance.",
    )
    test_fixtures: list[str] = Field(
        default_factory=list,
        description="Representative test fixture identifiers for this rule.",
    )
    false_positive_considerations: str = Field(
        ...,
        min_length=1,
        description="Contexts where this rule should be suppressed or adjusted.",
    )
    implemented: bool = Field(
        default=False,
        description="Whether deterministic analyzer detection is implemented for this rule.",
    )
    detection_fn: DetectionFunction | None = Field(
        default=None,
        exclude=True,
        description="Optional callable implementing rule detection.",
    )

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not _RULE_ID_REGEX.match(cleaned):
            raise ValueError(f"Invalid rule_id '{value}'. Must match ^[A-Z]{{2,4}}[0-9]{{3}}$.")
        return cleaned


class RuleRegistry:
    """Thread-safe in-memory registry of diagnostic rule definitions."""

    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, rule: RuleDefinition, *, overwrite: bool = False) -> None:
        """Register a `RuleDefinition` in the registry.

        Raises:
            RuleRegistrationError: If `rule.rule_id` is already registered and `overwrite=False`.
        """
        if rule.rule_id in self._rules and not overwrite:
            raise RuleRegistrationError(
                f"Rule '{rule.rule_id}' is already registered.",
                details={"rule_id": rule.rule_id},
            )
        self._rules[rule.rule_id] = rule

    def register_many(self, rules: Sequence[RuleDefinition], *, overwrite: bool = False) -> None:
        """Register multiple rule definitions."""
        for rule in rules:
            self.register(rule, overwrite=overwrite)

    def get(self, rule_id: str) -> RuleDefinition:
        """Retrieve a registered rule definition by ID.

        Raises:
            RuleRegistrationError: If `rule_id` is not found in the registry.
        """
        cleaned = rule_id.strip().upper()
        if cleaned not in self._rules:
            raise RuleRegistrationError(
                f"Rule '{rule_id}' is not registered.",
                details={"rule_id": rule_id},
            )
        return self._rules[cleaned]

    def has(self, rule_id: str) -> bool:
        """Return True if `rule_id` is present in the registry."""
        return rule_id.strip().upper() in self._rules

    def list_rules(
        self,
        *,
        category: Category | None = None,
        implemented_only: bool | None = None,
    ) -> list[RuleDefinition]:
        """Return registered rules sorted deterministically by `rule_id`."""
        rules = list(self._rules.values())
        if category is not None:
            rules = [r for r in rules if r.category == category]
        if implemented_only is not None:
            rules = [r for r in rules if r.implemented is implemented_only]
        return sorted(rules, key=lambda r: r.rule_id)

    def __len__(self) -> int:
        return len(self._rules)

    def create_finding(
        self,
        *,
        finding_id: str,
        rule_id: str,
        observed: Any,
        expected: Any,
        details: dict[str, Any] | None = None,
        title: str | None = None,
        description: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        file: str | None = None,
        line: int | None = None,
        recommendation: str | None = None,
        related_findings: list[str] | None = None,
        status: FindingStatus = FindingStatus.OPEN,
    ) -> Finding:
        """Construct a validated `Finding` linked to a registered `RuleDefinition`."""
        rule = self.get(rule_id)
        return Finding(
            id=finding_id,
            rule_id=rule.rule_id,
            title=title or rule.name,
            description=description or rule.description,
            severity=severity or rule.default_severity,
            confidence=confidence,
            category=rule.category,
            file=file,
            line=line,
            evidence=Evidence(
                observed=observed,
                expected=expected,
                details=details or {},
            ),
            recommendation=recommendation or rule.remediation_guidance,
            related_findings=related_findings or [],
            status=status,
        )
