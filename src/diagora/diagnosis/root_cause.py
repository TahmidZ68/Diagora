"""Root-cause hypothesis synthesis interface."""

from __future__ import annotations

from collections.abc import Sequence

from diagora.core.models import DiagnosticIssue, Finding
from diagora.diagnosis.confidence import aggregate_confidence
from diagora.diagnosis.severity import highest_severity


class RootCauseSynthesizer:
    """Synthesizes `DiagnosticIssue` objects from correlated finding clusters."""

    def build_issue(
        self,
        *,
        issue_id: str,
        title: str,
        hypothesis: str,
        findings: Sequence[Finding],
        next_action: str,
    ) -> DiagnosticIssue:
        """Create a validated `DiagnosticIssue` from a cluster of related findings."""
        return DiagnosticIssue(
            id=issue_id,
            title=title,
            root_cause_hypothesis=hypothesis,
            related_finding_ids=[f.id for f in findings],
            supporting_evidence=[
                f"[{f.rule_id}] {f.title} ({f.file or 'repository'}): "
                f"observed={f.evidence.observed}"
                for f in findings
            ],
            severity=highest_severity([f.severity for f in findings]),
            confidence=aggregate_confidence([f.confidence for f in findings]),
            suggested_next_action=next_action,
        )
