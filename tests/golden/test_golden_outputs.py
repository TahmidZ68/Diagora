"""Golden snapshot tests verifying deterministic diagnostic output stability."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from diagora.core.orchestrator import ScanOrchestrator
from diagora.reporting.json import serialize_scan_result

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
SNAPSHOTS_DIR = Path(__file__).resolve().parent / "snapshots"

GOLDEN_CASES: tuple[str, ...] = (
    "python/valid-uv",
    "python/broken-deps-and-entrypoints",
    "node/broken-node-project",
    "node/lockfile-mismatch",
    "mixed/monorepo",
)


@pytest.mark.parametrize("fixture_rel", GOLDEN_CASES)
def test_golden_json_output_matches_snapshot_and_is_deterministic(fixture_rel: str) -> None:
    fixture_path = FIXTURES_DIR / fixture_rel
    snapshot_name = fixture_rel.replace("/", "__") + ".json"
    expected_payload = json.loads((SNAPSHOTS_DIR / snapshot_name).read_text(encoding="utf-8"))

    orchestrator = ScanOrchestrator()
    first = json.loads(serialize_scan_result(orchestrator.scan(fixture_path)))
    second = json.loads(serialize_scan_result(orchestrator.scan(fixture_path)))

    first["scan_timestamp"] = "<TIMESTAMP>"
    second["scan_timestamp"] = "<TIMESTAMP>"

    assert first == second
    assert first == expected_payload
