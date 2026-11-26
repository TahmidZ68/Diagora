"""Diagnostic rules registry and definitions."""

from __future__ import annotations

from diagora.rules.definitions.catalog import INITIAL_RULES, build_default_rule_registry
from diagora.rules.registry import RuleDefinition, RuleRegistry

__all__ = [
    "INITIAL_RULES",
    "RuleDefinition",
    "RuleRegistry",
    "build_default_rule_registry",
]
