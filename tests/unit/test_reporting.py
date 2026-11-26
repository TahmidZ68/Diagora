"""Unit tests for JSON, Markdown, SARIF, and Rich terminal report serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from diagora import SCHEMA_VERSION, __version__
from diagora.core.exceptions import InvalidArgumentError
from diagora.core.models import (
    Confidence,
    Ecosystem,
    RepositoryContext,
    ScanResult,
    ScanSummary,
    Severity,
)
from diagora.reporting.json import (
    serialize_rules_json,
    serialize_scan_result,
    write_report_file,
)
from diagora.reporting.markdown import serialize_markdown_report
from diagora.reporting.sarif import serialize_sarif_report
from diagora.reporting.terminal import TerminalRenderer
from diagora.rules.definitions.catalog import build_default_rule_registry


def _make_sample_scan_result() -> ScanResult:
    registry = build_default_rule_registry()
    finding = registry.create_finding(
        finding_id="finding-001",
        rule_id="DK001",
        observed="missing/Dockerfile",
        expected="Existing Dockerfile",
        file="compose.yaml",
        line=8,
        confidence=Confidence.CONFIRMED,
    )
    ctx = RepositoryContext(
        repository_name="sample-repo",
        is_git_repository=True,
        detected_ecosystems=[Ecosystem.DOCKER, Ecosystem.PYTHON],
        package_managers=["uv"],
        manifests=["pyproject.toml"],
        lockfiles=["uv.lock"],
        docker_files=["compose.yaml"],
        total_files_inspected=5,
    )
    summary = ScanSummary(
        total_findings=1,
        total_issues=0,
        by_severity={
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFORMATIONAL.value: 0,
        },
        policy_passed=True,
    )
    return ScanResult(
        repository=ctx,
        findings=[finding],
        summary=summary,
    )


def test_json_serialization_versioned_envelope() -> None:
    result = _make_sample_scan_result()
    raw_json = serialize_scan_result(result)
    parsed = json.loads(raw_json)

    assert parsed["schema_version"] == SCHEMA_VERSION
    assert parsed["product_name"] == "diagora"
    assert parsed["product_version"] == __version__
    assert parsed["repository"]["repository_name"] == "sample-repo"
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["rule_id"] == "DK001"
    assert parsed["findings"][0]["file"] == "compose.yaml"
    assert parsed["findings"][0]["line"] == 8


def test_rules_json_serialization() -> None:
    registry = build_default_rule_registry()
    raw_json = serialize_rules_json(registry.list_rules())
    parsed = json.loads(raw_json)

    assert parsed["schema_version"] == SCHEMA_VERSION
    assert parsed["total_rules"] == 39
    assert parsed["rules"][0]["rule_id"] == "DK001"


def test_markdown_and_sarif_serialization() -> None:
    result = _make_sample_scan_result()

    md = serialize_markdown_report(result)
    assert "# Diagora Diagnostic Report — `sample-repo`" in md
    assert "`DK001`" in md
    assert "`compose.yaml:8`" in md

    sarif_str = serialize_sarif_report(result)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Diagora"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "DK001"
    assert (
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        == "compose.yaml"
    )


def test_terminal_renderer_outputs_readable_summary() -> None:
    result = _make_sample_scan_result()
    renderer = TerminalRenderer()
    text = renderer.render_scan_result_text(result, doctor_mode=True)
    assert "Diagora Doctor" in text
    assert "sample-repo" in text
    assert "DK001" in text


def test_write_report_file_validation(tmp_path: Path) -> None:
    out_file = tmp_path / "reports" / "out.json"
    saved = write_report_file('{"ok": true}', out_file)
    assert saved.exists()
    assert json.loads(saved.read_text(encoding="utf-8")) == {"ok": True}

    with pytest.raises(InvalidArgumentError):
        write_report_file('{"ok": true}', tmp_path)
