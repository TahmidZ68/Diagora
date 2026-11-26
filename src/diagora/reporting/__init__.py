"""Reporting engines for terminal, JSON, Markdown, and SARIF 2.1.0 outputs."""

from __future__ import annotations

from diagora.reporting.json import (
    serialize_rules_json,
    serialize_scan_result,
    write_report_file,
)
from diagora.reporting.markdown import serialize_markdown_report
from diagora.reporting.sarif import serialize_sarif_report
from diagora.reporting.terminal import TerminalRenderer

__all__ = [
    "TerminalRenderer",
    "serialize_markdown_report",
    "serialize_rules_json",
    "serialize_sarif_report",
    "serialize_scan_result",
    "write_report_file",
]
