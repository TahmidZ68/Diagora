"""Registry for pluggable static analyzers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diagora.core.exceptions import AnalyzerRegistrationError

if TYPE_CHECKING:
    from diagora.analyzers.base import BaseAnalyzer


class AnalyzerRegistry:
    """Ordered registry of static analyzers executed by the scan orchestrator."""

    def __init__(self) -> None:
        self._analyzers: dict[str, BaseAnalyzer] = {}

    def register(self, analyzer: BaseAnalyzer, *, overwrite: bool = False) -> None:
        """Register an analyzer instance by its unique `name`."""
        key = getattr(analyzer, "name", "").strip()
        if not key:
            raise AnalyzerRegistrationError("Analyzer must define a non-empty 'name'.")
        if key in self._analyzers and not overwrite:
            raise AnalyzerRegistrationError(
                f"Analyzer '{key}' is already registered.",
                details={"analyzer": key},
            )
        self._analyzers[key] = analyzer

    def get(self, name: str) -> BaseAnalyzer:
        """Retrieve a registered analyzer by name."""
        if name not in self._analyzers:
            raise AnalyzerRegistrationError(
                f"Analyzer '{name}' is not registered.",
                details={"analyzer": name},
            )
        return self._analyzers[name]

    def list_analyzers(self) -> list[BaseAnalyzer]:
        """Return all registered analyzers in deterministic name order."""
        return [self._analyzers[k] for k in sorted(self._analyzers.keys())]

    def __len__(self) -> int:
        return len(self._analyzers)
