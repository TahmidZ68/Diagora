"""Confidence level aggregation utilities for root-cause hypotheses."""

from __future__ import annotations

from collections.abc import Sequence

from diagora.core.models import Confidence


def aggregate_confidence(confidences: Sequence[Confidence]) -> Confidence:
    """Determine conservative aggregate confidence across correlated findings."""
    if not confidences:
        return Confidence.LOW
    return min(confidences, key=lambda c: c.rank)
