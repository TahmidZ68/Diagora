"""Explicit approval gate for narrowly scoped remediation patches (Phase 5 foundation)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    """Explicit authorization token for applying a specific rule's previewed patch."""

    rule_id: str
    target_file: str
    approved: bool = False
