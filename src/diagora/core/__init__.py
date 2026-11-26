"""Core domain models, discovery, security, and scan orchestration for Diagora."""

from __future__ import annotations

from diagora.core.classifier import ProjectClassifier
from diagora.core.discovery import (
    DiscoveryResult,
    FileSystemRepositoryDiscoverer,
    RepositoryDiscoverer,
)
from diagora.core.exceptions import (
    AnalyzerRegistrationError,
    DiagnosticExecutionError,
    DiagoraError,
    ExitCode,
    InvalidArgumentError,
    InvalidRepositoryPathError,
    PathSecurityError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
    ResourceLimitExceededError,
    RuleRegistrationError,
    UnsupportedScanError,
)
from diagora.core.models import (
    Category,
    Confidence,
    DiagnosticIssue,
    Ecosystem,
    Evidence,
    Finding,
    FindingStatus,
    RepositoryContext,
    ScanResult,
    ScanSummary,
    Severity,
    SubprojectInfo,
    VerificationState,
)
from diagora.core.orchestrator import ScanOrchestrator
from diagora.core.registry import AnalyzerRegistry
from diagora.core.scanner import RepositoryScanner

__all__ = [
    "AnalyzerRegistrationError",
    "AnalyzerRegistry",
    "Category",
    "Confidence",
    "DiagnosticExecutionError",
    "DiagnosticIssue",
    "DiagoraError",
    "DiscoveryResult",
    "Ecosystem",
    "Evidence",
    "ExitCode",
    "FileSystemRepositoryDiscoverer",
    "Finding",
    "FindingStatus",
    "InvalidArgumentError",
    "InvalidRepositoryPathError",
    "PathSecurityError",
    "ProjectClassifier",
    "RepositoryContext",
    "RepositoryDiscoverer",
    "RepositoryNotFoundError",
    "RepositoryPermissionError",
    "RepositoryScanner",
    "ResourceLimitExceededError",
    "RuleRegistrationError",
    "ScanOrchestrator",
    "ScanResult",
    "ScanSummary",
    "Severity",
    "SubprojectInfo",
    "UnsupportedScanError",
    "VerificationState",
]
