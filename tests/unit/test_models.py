"""Unit tests for Pydantic domain models, validation rules, and severity/confidence ordering."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from diagora import SCHEMA_VERSION, __version__
from diagora.core.models import (
    Category,
    Confidence,
    DiagnosticIssue,
    Ecosystem,
    Evidence,
    Finding,
    FindingStatus,
    RepositoryContext,
    ScanResult,
    Severity,
    VerificationState,
)


def test_severity_ranking_and_thresholds() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFORMATIONAL.rank
    assert Severity.HIGH.meets_threshold(Severity.MEDIUM) is True
    assert Severity.HIGH.meets_threshold(Severity.HIGH) is True
    assert Severity.LOW.meets_threshold(Severity.HIGH) is False


def test_confidence_ranking() -> None:
    assert Confidence.CONFIRMED.rank > Confidence.HIGH.rank
    assert Confidence.HIGH.rank > Confidence.MEDIUM.rank > Confidence.LOW.rank


def test_finding_validation_valid_model() -> None:
    finding = Finding(
        id="finding-001",
        rule_id="DK001",
        title="Dockerfile not found",
        description="The configured Dockerfile does not exist.",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category=Category.DOCKER,
        file="compose.yaml",
        line=12,
        evidence=Evidence(
            observed="backend/Dockerfile",
            expected="Existing file",
        ),
        recommendation="Correct the Dockerfile path.",
        related_findings=[],
        status=FindingStatus.OPEN,
    )
    assert finding.rule_id == "DK001"
    assert finding.file == "compose.yaml"
    assert finding.line == 12
    assert finding.status == FindingStatus.OPEN


@pytest.mark.parametrize(
    "invalid_rule_id",
    ["dk001", "D001", "DOCKER001", "PY01", "PY0001", "12345", ""],
)
def test_finding_rejects_invalid_rule_ids(invalid_rule_id: str) -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="finding-001",
            rule_id=invalid_rule_id,
            title="Test",
            description="Test description",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category=Category.PYTHON,
            evidence=Evidence(observed="a", expected="b"),
            recommendation="Fix it",
        )


@pytest.mark.parametrize(
    "bad_path",
    [
        "/etc/passwd",
        "../secret.txt",
        "subdir/../../outside.toml",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "\\\\server\\share\\file.txt",
        "   ",
    ],
)
def test_finding_rejects_unsafe_or_absolute_file_paths(bad_path: str) -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="finding-001",
            rule_id="PY001",
            title="Unsafe file path",
            description="Should fail validation",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            category=Category.PYTHON,
            file=bad_path,
            evidence=Evidence(observed="x", expected="y"),
            recommendation="Use relative path",
        )


def test_finding_rejects_non_positive_line_number() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="finding-001",
            rule_id="PY001",
            title="Bad line",
            description="Line 0 is invalid",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            category=Category.PYTHON,
            file="pyproject.toml",
            line=0,
            evidence=Evidence(observed="a", expected="b"),
            recommendation="Fix line",
        )


def test_diagnostic_issue_validation() -> None:
    issue = DiagnosticIssue(
        id="issue-001",
        title="Incorrect Docker build configuration",
        root_cause_hypothesis="Compose build context points to missing Dockerfile.",
        related_finding_ids=["finding-001", "finding-002"],
        supporting_evidence=["compose.yaml references backend/Dockerfile"],
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        suggested_next_action="Update build.context and dockerfile in compose.yaml.",
    )
    assert issue.verification_state == VerificationState.UNVERIFIED
    assert len(issue.related_finding_ids) == 2


def test_scan_result_versioned_envelope_defaults() -> None:
    ctx = RepositoryContext(
        repository_name="demo-repo",
        detected_ecosystems=[Ecosystem.PYTHON],
    )
    result = ScanResult(repository=ctx)
    assert result.schema_version == SCHEMA_VERSION
    assert result.product_name == "diagora"
    assert result.product_version == __version__
    assert result.summary.policy_passed is True
    assert result.verification_status == VerificationState.NOT_APPLICABLE
