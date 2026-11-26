"""Post-remediation verification interface (Phase 5 foundation)."""

from __future__ import annotations

from typing import Protocol

from diagora.core.models import VerificationState


class RemediationVerifier(Protocol):
    """Protocol for verifying that an applied remediation resolved the original finding."""

    def verify_finding_resolved(self, finding_id: str) -> VerificationState:
        """Re-run targeted checks and return the updated `VerificationState`."""
