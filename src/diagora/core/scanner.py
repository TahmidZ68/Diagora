"""Repository scanner coordinating file discovery, classification, and analyzer execution."""

from __future__ import annotations

from pathlib import Path

from diagora.core.classifier import ProjectClassifier
from diagora.core.discovery import (
    DiscoveryResult,
    FileSystemRepositoryDiscoverer,
    RepositoryDiscoverer,
)
from diagora.core.models import Finding, RepositoryContext
from diagora.core.registry import AnalyzerRegistry
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings


class RepositoryScanner:
    """Executes repository discovery, classification, and registered static analyzers."""

    def __init__(
        self,
        *,
        discoverer: RepositoryDiscoverer | None = None,
        classifier: ProjectClassifier | None = None,
        analyzer_registry: AnalyzerRegistry | None = None,
    ) -> None:
        self._discoverer = discoverer or FileSystemRepositoryDiscoverer()
        self._classifier = classifier or ProjectClassifier()
        self._analyzer_registry = analyzer_registry or AnalyzerRegistry()

    @property
    def analyzer_registry(self) -> AnalyzerRegistry:
        """Return the underlying `AnalyzerRegistry`."""
        return self._analyzer_registry

    def discover_and_classify(
        self,
        repo_root: Path,
        settings: ScanSettings,
    ) -> tuple[DiscoveryResult, RepositoryContext]:
        """Run filesystem discovery and project classification."""
        discovery = self._discoverer.discover(repo_root, settings)
        context = self._classifier.classify(discovery)
        return discovery, context

    def run_analyzers(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> tuple[list[Finding], list[str]]:
        """Execute supported analyzers and return `(findings, executed_analyzer_names)`."""
        findings: list[Finding] = []
        executed: list[str] = []
        for analyzer in self._analyzer_registry.list_analyzers():
            if analyzer.supports(context):
                executed.append(analyzer.name)
                findings.extend(
                    analyzer.analyze(
                        repo_root=repo_root,
                        context=context,
                        settings=settings,
                        rule_registry=rule_registry,
                    )
                )
        return findings, executed
