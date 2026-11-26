"""Unit and fixture tests for NodeAnalyzer (ND001-ND009)."""

from __future__ import annotations

from pathlib import Path

from diagora.core.models import Confidence, Severity
from diagora.core.orchestrator import ScanOrchestrator

FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "node"


def test_valid_node_fixtures_produce_zero_findings() -> None:
    for name in ("valid-npm", "valid-pnpm", "valid-yarn", "valid-workspace"):
        res = ScanOrchestrator().scan(FIXTURES_ROOT / name)
        assert res.summary.execution_status == "completed"
        assert "node" in res.summary.analyzers_executed
        assert res.findings == [], f"Unexpected findings for {name}: {res.findings}"


def test_broken_package_json_triggers_nd001() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "broken-package-json")
    assert len(res.findings) == 1
    assert res.findings[0].rule_id == "ND001"
    assert res.findings[0].file == "package.json"
    assert res.findings[0].severity == Severity.HIGH


def test_broken_node_project_detects_nd003_nd005_nd006_nd008() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "broken-node-project")
    rule_ids = {f.rule_id for f in res.findings}
    assert {"ND003", "ND005", "ND006", "ND008"}.issubset(rule_ids)


def test_lockfile_mismatch_triggers_nd009() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "lockfile-mismatch")
    assert [f.rule_id for f in res.findings] == ["ND009"]
    obs = str(res.findings[0].evidence.observed)
    assert "lodash" in obs
    assert "chalk" in obs


def test_broken_workspace_triggers_nd007() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "broken-workspace")
    nd007 = [f for f in res.findings if f.rule_id == "ND007"]
    assert len(nd007) == 2
    observed_all = " ".join(str(f.evidence.observed) for f in nd007)
    assert "missing-apps/*" in observed_all
    assert "@broken/ghost" in observed_all


def test_nested_standalone_projects_do_not_falsely_trigger_nd003(tmp_path: Path) -> None:
    repo = tmp_path / "nested-standalone"
    repo.mkdir()
    web = repo / "web-app"
    admin = repo / "admin-app"
    web.mkdir()
    admin.mkdir()

    (web / "package.json").write_text(
        '{"name": "web", "packageManager": "npm@10.5.0", "engines": {"node": ">=20"}}\n',
        encoding="utf-8",
    )
    (web / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

    (admin / "package.json").write_text(
        '{"name": "admin", "packageManager": "yarn@1.22.22", "engines": {"node": ">=20"}}\n',
        encoding="utf-8",
    )
    (admin / "yarn.lock").write_text(
        '# yarn lockfile v1\n"ms@^2.1.3":\n  version "2.1.3"\n', encoding="utf-8"
    )

    res = ScanOrchestrator().scan(repo)
    assert all(f.rule_id != "ND003" for f in res.findings)


def test_npmrc_engine_strict_elevates_nd004_and_nvmrc_mismatch(tmp_path: Path) -> None:
    repo = tmp_path / "strict-node"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"name": "strict-app", "packageManager": "npm@10.5.0"}\n',
        encoding="utf-8",
    )
    (repo / ".npmrc").write_text("engine-strict=true\n", encoding="utf-8")

    res = ScanOrchestrator().scan(repo)
    nd004 = [f for f in res.findings if f.rule_id == "ND004"]
    assert len(nd004) == 1
    assert nd004[0].severity == Severity.HIGH

    # Now add conflicting engines.node and .nvmrc
    (repo / "package.json").write_text(
        '{"name": "strict-app", "packageManager": "npm@10.5.0", "engines": {"node": ">=20"}}\n',
        encoding="utf-8",
    )
    (repo / ".nvmrc").write_text("v18.19.0\n", encoding="utf-8")
    res_mismatch = ScanOrchestrator().scan(repo)
    nd004_mismatch = [f for f in res_mismatch.findings if f.rule_id == "ND004"]
    assert len(nd004_mismatch) == 1
    assert "mismatch" in nd004_mismatch[0].title.lower()


def test_tsconfig_outdir_missing_main_lowers_severity_and_confidence(tmp_path: Path) -> None:
    repo = tmp_path / "ts-unbuilt"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"name": "ts-lib", "packageManager": "npm@10.5.0", '
        '"engines": {"node": ">=20"}, "main": "dist/index.js"}\n',
        encoding="utf-8",
    )
    (repo / "tsconfig.json").write_text(
        '{"compilerOptions": {"outDir": "dist"}}\n',
        encoding="utf-8",
    )
    res = ScanOrchestrator().scan(repo)
    nd006 = [f for f in res.findings if f.rule_id == "ND006"]
    assert len(nd006) == 1
    assert nd006[0].severity == Severity.LOW
    assert nd006[0].confidence == Confidence.MEDIUM
