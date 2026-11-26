"""Severity ordering, filtering, and aggregation utilities."""

from __future__ import annotations

from collections.abc import Sequence

from diagora.core.models import Finding, Severity


def highest_severity(severities: Sequence[Severity]) -> Severity:
    """Return the highest impact severity from a non-empty sequence."""
    if not severities:
        return Severity.INFORMATIONAL
    return max(severities, key=lambda s: s.rank)


def count_by_severity(findings: Sequence[Finding]) -> dict[str, int]:
    """Compute finding counts for every `Severity` level in canonical order."""
    counts: dict[str, int] = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def filter_by_min_severity(
    findings: Sequence[Finding],
    min_severity: Severity,
) -> list[Finding]:
    """Filter findings to those meeting or exceeding `min_severity`."""
    return [f for f in findings if f.severity.meets_threshold(min_severity)]
