"""Static analyzers package and default analyzer registry builder."""

from __future__ import annotations

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.node import NodeAnalyzer
from diagora.analyzers.python import PythonAnalyzer
from diagora.core.registry import AnalyzerRegistry


def build_default_analyzer_registry() -> AnalyzerRegistry:
    """Create an `AnalyzerRegistry` populated with all implemented static analyzers."""
    registry = AnalyzerRegistry()
    registry.register(PythonAnalyzer())
    registry.register(NodeAnalyzer())
    return registry


__all__ = [
    "BaseAnalyzer",
    "NodeAnalyzer",
    "PythonAnalyzer",
    "build_default_analyzer_registry",
]
