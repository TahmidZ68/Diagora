"""Diagnosis normalization, correlation, and root-cause analysis package."""

from __future__ import annotations

from diagora.diagnosis.confidence import aggregate_confidence
from diagora.diagnosis.correlator import FindingCorrelator
from diagora.diagnosis.normalizer import FindingNormalizer
from diagora.diagnosis.root_cause import RootCauseSynthesizer
from diagora.diagnosis.severity import (
    count_by_severity,
    filter_by_min_severity,
    highest_severity,
)

__all__ = [
    "FindingCorrelator",
    "FindingNormalizer",
    "RootCauseSynthesizer",
    "aggregate_confidence",
    "count_by_severity",
    "filter_by_min_severity",
    "highest_severity",
]
