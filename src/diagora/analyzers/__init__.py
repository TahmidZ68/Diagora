"""Static analyzers package and default analyzer registry builder."""

from __future__ import annotations

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.deployment import DeploymentAnalyzer
from diagora.analyzers.docker import DockerAnalyzer
from diagora.analyzers.environment import EnvironmentAnalyzer
from diagora.analyzers.node import NodeAnalyzer
from diagora.analyzers.python import PythonAnalyzer
from diagora.core.registry import AnalyzerRegistry


def build_default_analyzer_registry() -> AnalyzerRegistry:
    """Create an `AnalyzerRegistry` populated with all implemented static analyzers."""
    registry = AnalyzerRegistry()
    registry.register(DeploymentAnalyzer())
    registry.register(DockerAnalyzer())
    registry.register(EnvironmentAnalyzer())
    registry.register(PythonAnalyzer())
    registry.register(NodeAnalyzer())
    return registry


__all__ = [
    "BaseAnalyzer",
    "DeploymentAnalyzer",
    "DockerAnalyzer",
    "EnvironmentAnalyzer",
    "NodeAnalyzer",
    "PythonAnalyzer",
    "build_default_analyzer_registry",
]
