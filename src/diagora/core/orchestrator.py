"""Top-level scan orchestrator coordinating discovery, analyzers, normalization, and correlation."""

from __future__ import annotations

from pathlib import Path

from diagora.analyzers import build_default_analyzer_registry
from diagora.core.models import ScanResult, ScanSummary
from diagora.core.registry import AnalyzerRegistry
from diagora.core.scanner import RepositoryScanner
from diagora.core.security import redact_secrets, validate_repository_root
from diagora.diagnosis.correlator import FindingCorrelator
from diagora.diagnosis.normalizer import FindingNormalizer
from diagora.diagnosis.severity import count_by_severity, filter_by_min_severity
from diagora.rules.definitions.catalog import build_default_rule_registry
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings


class ScanOrchestrator:
    """Orchestrates end-to-end deterministic repository diagnostic scans."""

    def __init__(
        self,
        *,
        settings: ScanSettings | None = None,
        rule_registry: RuleRegistry | None = None,
        analyzer_registry: AnalyzerRegistry | None = None,
        scanner: RepositoryScanner | None = None,
        correlator: FindingCorrelator | None = None,
    ) -> None:
        self._settings = settings or ScanSettings()
        self._rule_registry = rule_registry or build_default_rule_registry()
        self._analyzer_registry = analyzer_registry or build_default_analyzer_registry()
        self._scanner = scanner or RepositoryScanner(analyzer_registry=self._analyzer_registry)
        self._normalizer = FindingNormalizer(self._rule_registry)
        self._correlator = correlator or FindingCorrelator()

    @property
    def settings(self) -> ScanSettings:
        """Return active scan settings."""
        return self._settings

    @property
    def rule_registry(self) -> RuleRegistry:
        """Return active rule registry."""
        return self._rule_registry

    @property
    def analyzer_registry(self) -> AnalyzerRegistry:
        """Return active analyzer registry."""
        return self._analyzer_registry

    def scan(self, target_path: Path | str) -> ScanResult:
        """Execute a full diagnostic scan on `target_path` and return a validated `ScanResult`."""
        resolved_root = validate_repository_root(target_path)
        discovery, context = self._scanner.discover_and_classify(
            resolved_root,
            self._settings,
        )

        warnings: list[str] = [redact_secrets(w) for w in discovery.warnings]

        if context.unsupported_files and not context.detected_ecosystems:
            warnings.append(
                "Detected project files for unsupported ecosystems ("
                + ", ".join(context.unsupported_files[:5])
                + "). Only Python, Node.js, Docker, and supported "
                "deployment manifests are analyzed."
            )

        raw_findings, analyzers_executed = self._scanner.run_analyzers(
            resolved_root,
            context,
            self._settings,
            self._rule_registry,
        )

        execution_status = "completed"
        if not context.is_empty and not analyzers_executed:
            execution_status = "no_applicable_analyzers"
            if not any("unsupported ecosystems" in w for w in warnings):
                warnings.append(
                    "No implemented static analyzer applied to the discovered files; "
                    "no clean-scan guarantee can be claimed for this repository."
                )

        normalized_findings = self._normalizer.normalize(raw_findings)
        filtered_findings = filter_by_min_severity(
            normalized_findings,
            self._settings.min_report_severity,
        )
        issues = self._correlator.correlate(filtered_findings)

        policy_passed = True
        if self._settings.fail_on_severity is not None:
            threshold = self._settings.fail_on_severity
            if any(f.severity.meets_threshold(threshold) for f in filtered_findings):
                policy_passed = False

        summary = ScanSummary(
            total_findings=len(filtered_findings),
            total_issues=len(issues),
            by_severity=count_by_severity(filtered_findings),
            analyzers_executed=analyzers_executed,
            policy_passed=policy_passed,
            execution_status=execution_status,
        )

        return ScanResult(
            repository=context,
            findings=filtered_findings,
            issues=issues,
            summary=summary,
            runtime_enabled=self._settings.enable_runtime_probes,
            warnings=warnings,
        )
