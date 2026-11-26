"""Base Analyzer interface for all Diagora static diagnostic analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from diagora.core.models import Category, Ecosystem, Finding, RepositoryContext
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings


class BaseAnalyzer(ABC):
    """Abstract base class for pluggable static repository analyzers."""

    name: str
    category: Category
    supported_ecosystems: tuple[Ecosystem, ...] = ()

    def supports(self, context: RepositoryContext) -> bool:
        """Return True if this analyzer should run against `context`."""
        if context.is_empty:
            return False
        if not self.supported_ecosystems:
            return True
        return any(eco in context.detected_ecosystems for eco in self.supported_ecosystems)

    @abstractmethod
    def analyze(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> list[Finding]:
        """Inspect the repository and return deterministic findings."""
