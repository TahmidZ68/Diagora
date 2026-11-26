"""SARIF 2.1.0 report serializer for GitHub Code Scanning compatibility."""

from __future__ import annotations

import json
from typing import Any

from diagora.core.models import ScanResult, Severity
from diagora.core.security import redact_value

_SARIF_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}


def serialize_sarif_report(result: ScanResult, *, indent: int = 2) -> str:
    """Serialize a `ScanResult` into a valid SARIF 2.1.0 JSON document."""
    rules_map: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in result.findings:
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.recommendation},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL_MAP[finding.severity],
                },
            }

        locations: list[dict[str, Any]] = []
        if finding.file:
            physical_location: dict[str, Any] = {
                "artifactLocation": {"uri": finding.file},
            }
            if finding.line is not None:
                physical_location["region"] = {"startLine": finding.line}
            locations.append({"physicalLocation": physical_location})

        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL_MAP[finding.severity],
                "message": {
                    "text": f"{finding.description} Recommendation: {finding.recommendation}"
                },
                "locations": locations,
            }
        )

    sarif_envelope: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Diagora",
                        "version": result.product_version,
                        "informationUri": "https://github.com/TahmidZ68/Diagora",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(redact_value(sarif_envelope), indent=indent)
