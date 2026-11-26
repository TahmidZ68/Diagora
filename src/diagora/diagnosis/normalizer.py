"""Deterministic finding normalization and deduplication engine."""

from __future__ import annotations

from collections.abc import Sequence

from diagora.core.models import Finding
from diagora.rules.registry import RuleRegistry


class FindingNormalizer:
    """Normalizes, validates, deduplicates, and deterministically sorts findings."""

    def __init__(self, rule_registry: RuleRegistry) -> None:
        self._rule_registry = rule_registry

    def normalize(self, findings: Sequence[Finding]) -> list[Finding]:
        """Validate findings against registered rules, deduplicate, and sort deterministically."""
        seen_keys: set[tuple[str, str | None, int | None, str]] = set()
        unique_findings: list[Finding] = []

        for finding in findings:
            # Verify rule_id is registered
            self._rule_registry.get(finding.rule_id)
            dedup_key = (
                finding.rule_id,
                finding.file,
                finding.line,
                str(finding.evidence.observed),
            )
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            unique_findings.append(finding)

        # Deterministic sort: highest severity first, then rule_id, file, line
        sorted_findings = sorted(
            unique_findings,
            key=lambda f: (
                -f.severity.rank,
                f.rule_id,
                f.file or "",
                f.line or 0,
                f.id,
            ),
        )
        return sorted_findings
