"""Human-readable Rich terminal renderer for Diagora scans, doctor checks, and rules."""

from __future__ import annotations

from collections.abc import Sequence
from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from diagora.core.models import ScanResult, Severity
from diagora.core.security import redact_secrets
from diagora.rules.registry import RuleDefinition

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFORMATIONAL: "dim",
}


class TerminalRenderer:
    """Renders structured `ScanResult` and `RuleDefinition` catalogs for terminal output."""

    def print_scan_result(
        self,
        result: ScanResult,
        *,
        console: Console | None = None,
        doctor_mode: bool = False,
    ) -> None:
        """Render `result` directly to the provided Rich `Console`."""
        target_console = console or Console()
        repo = result.repository

        title_prefix = "Diagora Doctor" if doctor_mode else "Diagora Scan"
        ecosystems_str = (
            ", ".join(e.value for e in repo.detected_ecosystems)
            if repo.detected_ecosystems
            else "none detected"
        )
        pms_str = ", ".join(repo.package_managers) if repo.package_managers else "none"
        analyzers_str = (
            ", ".join(result.summary.analyzers_executed)
            if result.summary.analyzers_executed
            else "none"
        )

        summary_text = Text()
        summary_text.append("Repository: ", style="bold")
        summary_text.append(f"{repo.repository_name} ({repo.relative_path})\n")
        summary_text.append("Git Repository: ", style="bold")
        summary_text.append("yes" if repo.is_git_repository else "no")
        summary_text.append("  Monorepo: ", style="bold")
        summary_text.append("yes" if repo.is_monorepo else "no")
        summary_text.append("  Files Inspected: ", style="bold")
        summary_text.append(f"{repo.total_files_inspected}\n")
        summary_text.append("Ecosystems: ", style="bold")
        summary_text.append(ecosystems_str)
        summary_text.append("  Package Managers: ", style="bold")
        summary_text.append(f"{pms_str}\n")
        summary_text.append("Analyzers Executed: ", style="bold")
        summary_text.append(analyzers_str)
        summary_text.append("  Status: ", style="bold")
        summary_text.append(result.summary.execution_status)

        if doctor_mode:
            runtime_label = "enabled" if result.runtime_enabled else "disabled (static mode)"
            summary_text.append("\nManifests: ", style="bold")
            summary_text.append(f"{len(repo.manifests)}  ")
            summary_text.append("Lockfiles: ", style="bold")
            summary_text.append(f"{len(repo.lockfiles)}  ")
            summary_text.append("Docker Files: ", style="bold")
            summary_text.append(f"{len(repo.docker_files)}  ")
            summary_text.append("CI Workflows: ", style="bold")
            summary_text.append(f"{len(repo.ci_workflows)}\n")
            summary_text.append("Runtime Probes: ", style="bold")
            summary_text.append(runtime_label)

        panel_title = Text()
        panel_title.append(title_prefix, style="bold cyan")
        panel_title.append(f" v{result.product_version}", style="dim")

        target_console.print(Panel(summary_text, title=panel_title, expand=False))

        if repo.is_empty:
            target_console.print(
                Text("Empty repository detected (0 files inspected).", style="yellow")
            )

        for warning in result.warnings:
            warn_text = Text()
            warn_text.append("Warning: ", style="yellow")
            warn_text.append(redact_secrets(warning))
            target_console.print(warn_text)

        if not result.findings:
            if result.summary.execution_status == "no_applicable_analyzers":
                target_console.print(
                    Text(
                        "No applicable static analyzer executed for this repository "
                        "(not a verified clean scan).",
                        style="yellow",
                    )
                )
            else:
                target_console.print(Text("No diagnostic findings detected.", style="bold green"))
        else:
            findings_table = Table(
                title=f"Diagnostic Findings ({result.summary.total_findings})",
                show_lines=True,
            )
            findings_table.add_column("Rule", style="bold")
            findings_table.add_column("Severity")
            findings_table.add_column("Confidence")
            findings_table.add_column("Category")
            findings_table.add_column("Location")
            findings_table.add_column("Title & Recommendation")

            for finding in result.findings:
                loc = finding.file or "-"
                if finding.file and finding.line:
                    loc = f"{finding.file}:{finding.line}"
                sev_style = _SEVERITY_STYLES.get(finding.severity, "")

                details_text = Text()
                details_text.append(finding.title, style="bold")
                details_text.append("\nObserved: ", style="dim")
                details_text.append(redact_secrets(str(finding.evidence.observed)))
                details_text.append("\nFix: ", style="dim")
                details_text.append(finding.recommendation)

                findings_table.add_row(
                    Text(finding.rule_id, style="bold"),
                    Text(finding.severity.value.upper(), style=sev_style),
                    Text(finding.confidence.value),
                    Text(finding.category.value),
                    Text(loc),
                    details_text,
                )
            target_console.print(findings_table)

        if result.issues:
            issues_table = Table(
                title=f"Correlated Root-Cause Issues ({result.summary.total_issues})",
                show_lines=True,
            )
            issues_table.add_column("Issue ID", style="bold")
            issues_table.add_column("Severity")
            issues_table.add_column("Confidence")
            issues_table.add_column("Root-Cause Hypothesis & Next Action")

            for issue in result.issues:
                sev_style = _SEVERITY_STYLES.get(issue.severity, "")
                issue_text = Text()
                issue_text.append(issue.title, style="bold")
                issue_text.append(": ")
                issue_text.append(issue.root_cause_hypothesis)
                issue_text.append("\nFindings: ", style="dim")
                issue_text.append(", ".join(issue.related_finding_ids))
                issue_text.append("\nNext Action: ", style="dim")
                issue_text.append(issue.suggested_next_action)

                issues_table.add_row(
                    Text(issue.id, style="bold"),
                    Text(issue.severity.value.upper(), style=sev_style),
                    Text(issue.confidence.value),
                    issue_text,
                )
            target_console.print(issues_table)

    def render_scan_result_text(
        self,
        result: ScanResult,
        *,
        doctor_mode: bool = False,
    ) -> str:
        """Render a `ScanResult` to a plain text string."""
        buffer = StringIO()
        console = Console(file=buffer, force_terminal=False, color_system=None, width=140)
        self.print_scan_result(result, console=console, doctor_mode=doctor_mode)
        return buffer.getvalue()

    def print_rules_table(
        self,
        rules: Sequence[RuleDefinition],
        *,
        console: Console | None = None,
    ) -> None:
        """Render a table of registered `RuleDefinition` entries."""
        target_console = console or Console()
        impl_count = sum(1 for r in rules if r.implemented)
        deferred_count = len(rules) - impl_count
        table = Table(
            title=(
                f"Diagora Registered Rules ({len(rules)} total: "
                f"{impl_count} implemented, {deferred_count} deferred)"
            )
        )
        table.add_column("Rule ID", style="bold cyan", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Version", no_wrap=True)
        table.add_column("Name", style="bold")
        table.add_column("Description")

        for rule in rules:
            sev_style = _SEVERITY_STYLES.get(rule.default_severity, "")
            status_text = (
                Text("implemented", style="bold green")
                if rule.implemented
                else Text("deferred", style="dim")
            )
            table.add_row(
                Text(rule.rule_id, style="bold cyan"),
                Text(rule.category.value),
                Text(rule.default_severity.value, style=sev_style),
                status_text,
                Text(rule.version),
                Text(rule.name, style="bold"),
                Text(rule.description),
            )
        target_console.print(table)
