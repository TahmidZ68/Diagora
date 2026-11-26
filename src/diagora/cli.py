"""Typer Command-Line Interface for Diagora."""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text

from diagora import __version__
from diagora.core.exceptions import (
    DiagoraError,
    ExitCode,
    InvalidArgumentError,
)
from diagora.core.models import Category, ScanResult, Severity
from diagora.core.orchestrator import ScanOrchestrator
from diagora.core.security import redact_secrets, redact_value
from diagora.reporting.json import (
    serialize_rules_json,
    serialize_scan_result,
    write_report_file,
)
from diagora.reporting.markdown import serialize_markdown_report
from diagora.reporting.sarif import serialize_sarif_report
from diagora.reporting.terminal import TerminalRenderer
from diagora.rules.definitions.catalog import build_default_rule_registry
from diagora.settings import ScanSettings


class OutputFormat(str, Enum):
    """Supported report output formats."""

    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


app = typer.Typer(
    name="diagora",
    help="Diagora — Open-source developer diagnostics and root-cause intelligence CLI.",
    add_completion=False,
    no_args_is_help=True,
)

rules_app = typer.Typer(
    name="rules",
    help="Inspect and list registered diagnostic rules.",
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")

_stdout_console = Console()
_stderr_console = Console(stderr=True)
_renderer = TerminalRenderer()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"diagora {__version__}")
        raise typer.Exit(code=int(ExitCode.OK))


@app.callback()
def main_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show the Diagora version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Diagora: Find the cause. Verify the fix."""


def _parse_output_format(raw_format: str) -> OutputFormat:
    normalized = raw_format.strip().lower()
    if normalized == "md":
        normalized = "markdown"
    try:
        return OutputFormat(normalized)
    except ValueError as exc:
        valid = ", ".join(f.value for f in OutputFormat)
        raise InvalidArgumentError(
            f"Unsupported output format '{raw_format}'. Choose from: {valid}.",
            details={"format": raw_format},
        ) from exc


def _parse_severity(raw_severity: str | None) -> Severity | None:
    if raw_severity is None:
        return None
    normalized = raw_severity.strip().lower()
    try:
        return Severity(normalized)
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        raise InvalidArgumentError(
            f"Invalid severity '{raw_severity}'. Choose from: {valid}.",
            details={"severity": raw_severity},
        ) from exc


def _parse_category(raw_category: str | None) -> Category | None:
    if raw_category is None:
        return None
    normalized = raw_category.strip().lower()
    try:
        return Category(normalized)
    except ValueError as exc:
        valid = ", ".join(c.value for c in Category)
        raise InvalidArgumentError(
            f"Invalid category '{raw_category}'. Choose from: {valid}.",
            details={"category": raw_category},
        ) from exc


def _render_result_content(
    result: ScanResult,
    output_format: OutputFormat,
    *,
    doctor_mode: bool = False,
) -> str:
    if output_format == OutputFormat.JSON:
        return serialize_scan_result(result)
    if output_format == OutputFormat.MARKDOWN:
        return serialize_markdown_report(result)
    if output_format == OutputFormat.SARIF:
        return serialize_sarif_report(result)
    return _renderer.render_scan_result_text(result, doctor_mode=doctor_mode)


def _handle_diagora_error(exc: DiagoraError, *, as_json: bool = False) -> None:
    safe_message = redact_secrets(exc.message)
    if as_json:
        error_payload = {
            "error": {
                "code": exc.error_code,
                "message": safe_message,
                "details": redact_value(exc.details),
                "exit_code": int(exc.exit_code),
            }
        }
        typer.echo(json.dumps(error_payload, indent=2), err=True)
    else:
        err_text = Text()
        err_text.append(f"Error ({exc.error_code}): ", style="bold red")
        err_text.append(safe_message)
        _stderr_console.print(err_text)
    raise typer.Exit(code=int(exc.exit_code))


@app.command("scan")
def scan_command(
    path: Annotated[
        str,
        typer.Argument(help="Target repository path to scan."),
    ] = ".",
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: terminal, json, markdown, or sarif.",
        ),
    ] = "terminal",
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity threshold (informational, low, medium, high, critical).",
        ),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional file path to write the diagnostic report.",
        ),
    ] = None,
    no_ai: Annotated[
        bool,
        typer.Option(
            "--no-ai",
            help="Disable optional AI root-cause adapter (deterministic mode is default).",
        ),
    ] = False,
    runtime: Annotated[
        bool,
        typer.Option(
            "--runtime",
            help="Enable opt-in runtime environment checks.",
        ),
    ] = False,
) -> None:
    """Discover project structure and run deterministic diagnostics on a repository."""
    wants_json = output_format.strip().lower() == "json"
    try:
        fmt = _parse_output_format(output_format)
        sev_threshold = _parse_severity(severity)

        settings = ScanSettings(
            enable_runtime_probes=runtime,
            enable_ai_adapter=False,
            min_report_severity=sev_threshold or Severity.INFORMATIONAL,
            fail_on_severity=sev_threshold,
        )
        orchestrator = ScanOrchestrator(settings=settings)
        result = orchestrator.scan(path)

        if output is not None:
            content = _render_result_content(result, fmt, doctor_mode=False)
            write_report_file(content, output)

        if fmt == OutputFormat.TERMINAL:
            _renderer.print_scan_result(result, console=_stdout_console, doctor_mode=False)
        else:
            typer.echo(_render_result_content(result, fmt, doctor_mode=False))

        if not result.summary.policy_passed:
            raise typer.Exit(code=int(ExitCode.POLICY_FAILURE))
    except DiagoraError as exc:
        _handle_diagora_error(exc, as_json=wants_json)


@app.command("doctor")
def doctor_command(
    path: Annotated[
        str,
        typer.Argument(help="Target repository path to check."),
    ] = ".",
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: terminal or json.",
        ),
    ] = "terminal",
    runtime: Annotated[
        bool,
        typer.Option(
            "--runtime",
            help="Enable opt-in runtime environment probes.",
        ),
    ] = False,
) -> None:
    """Run repository health and environment readiness diagnostics."""
    wants_json = output_format.strip().lower() == "json"
    try:
        fmt = _parse_output_format(output_format)
        settings = ScanSettings(enable_runtime_probes=runtime)
        orchestrator = ScanOrchestrator(settings=settings)
        result = orchestrator.scan(path)

        if fmt == OutputFormat.TERMINAL:
            _renderer.print_scan_result(result, console=_stdout_console, doctor_mode=True)
        else:
            typer.echo(_render_result_content(result, fmt, doctor_mode=True))
    except DiagoraError as exc:
        _handle_diagora_error(exc, as_json=wants_json)


@app.command("report")
def report_command(
    path: Annotated[
        str,
        typer.Argument(help="Target repository path to scan."),
    ] = ".",
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path for the generated report (e.g., report.json).",
        ),
    ] = None,
    output_format: Annotated[
        str | None,
        typer.Option(
            "--format",
            "-f",
            help=(
                "Report format: json, markdown, sarif, or terminal "
                "(auto-detected from --output extension if omitted)."
            ),
        ),
    ] = None,
) -> None:
    """Generate a structured diagnostic report and write it to a file or stdout."""
    inferred_raw = output_format
    if inferred_raw is None:
        if output is not None:
            suffix = Path(output).suffix.lower()
            if suffix == ".md":
                inferred_raw = "markdown"
            elif suffix == ".sarif":
                inferred_raw = "sarif"
            else:
                inferred_raw = "json"
        else:
            inferred_raw = "json"

    wants_json = inferred_raw.strip().lower() == "json"
    try:
        fmt = _parse_output_format(inferred_raw)
        orchestrator = ScanOrchestrator()
        result = orchestrator.scan(path)
        content = _render_result_content(result, fmt, doctor_mode=False)

        if output is not None:
            saved_path = write_report_file(content, output)
            if fmt == OutputFormat.TERMINAL:
                _stdout_console.print(f"[green]Report written to:[/green] {saved_path.name}")
            else:
                typer.echo(content)
        else:
            typer.echo(content)
    except DiagoraError as exc:
        _handle_diagora_error(exc, as_json=wants_json)


@rules_app.command("list")
def rules_list_command(
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Filter rules by category (python, node, environment, docker, deployment).",
        ),
    ] = None,
    status: Annotated[
        str | None,
        typer.Option(
            "--status",
            help="Filter rules by implementation status: implemented, deferred, or all.",
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: terminal or json.",
        ),
    ] = "terminal",
) -> None:
    """List all registered diagnostic rules and their implementation status."""
    wants_json = output_format.strip().lower() == "json"
    try:
        fmt = _parse_output_format(output_format)
        cat = _parse_category(category)
        impl_filter: bool | None = None
        if status is not None:
            norm_status = status.strip().lower()
            if norm_status == "implemented":
                impl_filter = True
            elif norm_status == "deferred":
                impl_filter = False
            elif norm_status != "all":
                raise InvalidArgumentError(
                    f"Invalid rule status '{status}'. Choose from: implemented, deferred, all.",
                    details={"status": status},
                )
        registry = build_default_rule_registry()
        rules = registry.list_rules(category=cat, implemented_only=impl_filter)

        if fmt == OutputFormat.JSON:
            typer.echo(serialize_rules_json(rules))
        else:
            _renderer.print_rules_table(rules, console=_stdout_console)
    except DiagoraError as exc:
        _handle_diagora_error(exc, as_json=wants_json)


def main(args: list[str] | None = None) -> None:
    """CLI entry point for console script `diagora`."""
    try:
        app(args=args, standalone_mode=True)
    except SystemExit as exc:
        sys.exit(exc.code)


if __name__ == "__main__":
    main()
