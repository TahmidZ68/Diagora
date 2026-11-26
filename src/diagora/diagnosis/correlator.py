"""Finding correlation engine foundation."""

from __future__ import annotations

from collections.abc import Sequence

from diagora.core.models import DiagnosticIssue, Finding
from diagora.diagnosis.root_cause import RootCauseSynthesizer


class FindingCorrelator:
    """Correlates related findings into root-cause `DiagnosticIssue` groups."""

    def __init__(self, synthesizer: RootCauseSynthesizer | None = None) -> None:
        self._synthesizer = synthesizer or RootCauseSynthesizer()

    def correlate(self, findings: Sequence[Finding]) -> list[DiagnosticIssue]:
        """Group explicitly linked findings (`related_findings`) into diagnostic issues."""
        if not findings:
            return []

        by_id: dict[str, Finding] = {f.id: f for f in findings}
        visited: set[str] = set()
        issues: list[DiagnosticIssue] = []
        issue_index = 1

        for finding in findings:
            if finding.id in visited or not finding.related_findings:
                continue

            cluster: list[Finding] = [finding]
            visited.add(finding.id)
            for rel_id in finding.related_findings:
                if rel_id in by_id and rel_id not in visited:
                    cluster.append(by_id[rel_id])
                    visited.add(rel_id)

            if len(cluster) > 1:
                primary = cluster[0]
                issues.append(
                    self._synthesizer.build_issue(
                        issue_id=f"issue-{issue_index:03d}",
                        title=f"Correlated {primary.category.value} configuration issue",
                        hypothesis=primary.description,
                        findings=cluster,
                        next_action=primary.recommendation,
                    )
                )
                issue_index += 1

        return issues
