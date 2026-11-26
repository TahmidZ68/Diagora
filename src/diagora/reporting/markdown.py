"""Markdown report renderer for Diagora scan results."""

from __future__ import annotations

from diagora.core.models import ScanResult
from diagora.core.security import redact_secrets


def _escape_md_cell(value: str) -> str:
    """Escape Markdown table delimiters and line breaks while redacting secrets."""
    return redact_secrets(value).replace("|", "\\|").replace("\r\n", " ").replace("\n", " ")


def serialize_markdown_report(result: ScanResult) -> str:
    """Render a `ScanResult` as a clean GitHub-Flavored Markdown document."""
    repo = result.repository
    ecosystems = ", ".join(e.value for e in repo.detected_ecosystems) or "none"
    pms = ", ".join(repo.package_managers) or "none"
    analyzers = ", ".join(result.summary.analyzers_executed) or "none"

    lines: list[str] = [
        f"# Diagora Diagnostic Report — `{redact_secrets(repo.repository_name)}`",
        "",
        f"- **Product Version**: `{result.product_version}`",
        f"- **Schema Version**: `{result.schema_version}`",
        f"- **Timestamp**: `{result.scan_timestamp.isoformat()}`",
        f"- **Detected Ecosystems**: {ecosystems}",
        f"- **Package Managers**: {pms}",
        f"- **Analyzers Executed**: {analyzers}",
        f"- **Execution Status**: `{result.summary.execution_status}`",
        f"- **Git Repository**: `{'yes' if repo.is_git_repository else 'no'}`",
        f"- **Monorepo**: `{'yes' if repo.is_monorepo else 'no'}`",
        f"- **Files Inspected**: `{repo.total_files_inspected}`",
        f"- **Total Findings**: `{result.summary.total_findings}`",
        f"- **Policy Passed**: `{'yes' if result.summary.policy_passed else 'no'}`",
        "",
    ]

    if repo.is_empty:
        lines.append("> **Note:** Target repository is empty (0 files discovered).")
        lines.append("")

    if result.warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in result.warnings:
            lines.append(f"- {redact_secrets(warning)}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        if result.summary.execution_status == "no_applicable_analyzers":
            lines.append(
                "No applicable static analyzer executed for this repository "
                "(not a verified clean scan)."
            )
        else:
            lines.append("No diagnostic findings detected.")
        lines.append("")
    else:
        lines.append("| Rule | Severity | Confidence | File | Title | Observed | Recommendation |")
        lines.append("| ---- | -------- | ---------- | ---- | ----- | -------- | -------------- |")
        for finding in result.findings:
            loc = finding.file or "-"
            if finding.file and finding.line:
                loc = f"{finding.file}:{finding.line}"
            lines.append(
                f"| `{finding.rule_id}` | `{finding.severity.value}` "
                f"| `{finding.confidence.value}` "
                f"| `{_escape_md_cell(loc)}` | {_escape_md_cell(finding.title)} "
                f"| {_escape_md_cell(str(finding.evidence.observed))} "
                f"| {_escape_md_cell(finding.recommendation)} |"
            )
        lines.append("")

    if result.issues:
        lines.append("## Correlated Root-Cause Issues")
        lines.append("")
        for issue in result.issues:
            lines.append(
                f"### {issue.id}: {redact_secrets(issue.title)} (`{issue.severity.value}`)"
            )
            lines.append(f"- **Hypothesis**: {redact_secrets(issue.root_cause_hypothesis)}")
            lines.append(f"- **Confidence**: `{issue.confidence.value}`")
            lines.append(f"- **Related Findings**: {', '.join(issue.related_finding_ids)}")
            lines.append(f"- **Next Action**: {redact_secrets(issue.suggested_next_action)}")
            lines.append("")

    return "\n".join(lines)
