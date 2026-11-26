"""Unit tests for RuleDefinition, RuleRegistry, AnalyzerRegistry, and the built-in catalog."""

from __future__ import annotations

import pytest

from diagora.analyzers.base import BaseAnalyzer
from diagora.core.exceptions import AnalyzerRegistrationError, RuleRegistrationError
from diagora.core.models import Category, Confidence, Finding, Severity
from diagora.core.registry import AnalyzerRegistry
from diagora.rules.definitions.catalog import build_default_rule_registry
from diagora.rules.registry import RuleDefinition, RuleRegistry


def test_default_rule_catalog_contains_all_prd_rules() -> None:
    registry = build_default_rule_registry()
    all_rules = registry.list_rules()
    assert len(all_rules) == 39

    expected_prefixes = {
        Category.PYTHON: [f"PY{i:03d}" for i in range(1, 11)],
        Category.NODE: [f"ND{i:03d}" for i in range(1, 11)],
        Category.ENVIRONMENT: [f"ENV{i:03d}" for i in range(1, 7)],
        Category.DOCKER: [f"DK{i:03d}" for i in range(1, 11)],
        Category.DEPLOYMENT: [f"DP{i:03d}" for i in range(1, 4)],
    }

    for category, rule_ids in expected_prefixes.items():
        cat_rules = registry.list_rules(category=category)
        assert [r.rule_id for r in cat_rules] == rule_ids
        for rule_id in rule_ids:
            assert registry.has(rule_id)
            rule = registry.get(rule_id)
            assert rule.category == category
            assert rule.remediation_guidance
            assert rule.false_positive_considerations

    implemented = registry.list_rules(implemented_only=True)
    deferred = registry.list_rules(implemented_only=False)
    assert len(implemented) == 38
    assert len(deferred) == 1
    assert {r.rule_id for r in deferred} == {"ND010"}
    assert {r.rule_id for r in implemented} == {
        *(f"PY{i:03d}" for i in range(1, 11)),
        *(f"ND{i:03d}" for i in range(1, 10)),
        *(f"ENV{i:03d}" for i in range(1, 7)),
        *(f"DK{i:03d}" for i in range(1, 11)),
        *(f"DP{i:03d}" for i in range(1, 4)),
    }


def test_rule_registry_duplicate_and_missing_handling() -> None:
    registry = RuleRegistry()
    rule = RuleDefinition(
        rule_id="PY001",
        name="Missing Python version",
        description="Checks requires-python",
        category=Category.PYTHON,
        default_severity=Severity.MEDIUM,
        remediation_guidance="Add requires-python",
        false_positive_considerations="Single scripts",
    )
    registry.register(rule)
    assert len(registry) == 1

    with pytest.raises(RuleRegistrationError):
        registry.register(rule)

    # Overwrite allowed when explicitly flagged
    registry.register(rule, overwrite=True)

    with pytest.raises(RuleRegistrationError):
        registry.get("PY999")


def test_rule_registry_create_finding_factory() -> None:
    registry = build_default_rule_registry()
    finding = registry.create_finding(
        finding_id="finding-001",
        rule_id="DK001",
        observed="backend/Dockerfile",
        expected="Existing file",
        file="compose.yaml",
        line=12,
        confidence=Confidence.CONFIRMED,
    )
    assert finding.rule_id == "DK001"
    assert finding.severity == Severity.HIGH
    assert finding.category == Category.DOCKER
    assert finding.file == "compose.yaml"
    assert finding.line == 12
    assert finding.evidence.observed == "backend/Dockerfile"


def test_analyzer_registry_lifecycle() -> None:
    class DummyAnalyzer(BaseAnalyzer):
        name = "dummy"
        category = Category.PYTHON

        def analyze(self, repo_root, context, settings, rule_registry) -> list[Finding]:  # type: ignore[no-untyped-def]
            return []

    reg = AnalyzerRegistry()
    analyzer = DummyAnalyzer()
    reg.register(analyzer)
    assert len(reg) == 1
    assert reg.get("dummy") is analyzer
    assert reg.list_analyzers() == [analyzer]

    with pytest.raises(AnalyzerRegistrationError):
        reg.register(analyzer)

    with pytest.raises(AnalyzerRegistrationError):
        reg.get("nonexistent")
