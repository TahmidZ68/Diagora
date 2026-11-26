"""Integration tests for CLI commands, repository discovery, classification, and orchestration."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from diagora import SCHEMA_VERSION, __version__
from diagora.analyzers.base import BaseAnalyzer
from diagora.cli import app
from diagora.core.exceptions import ExitCode
from diagora.core.models import Category, Confidence, Ecosystem, Finding, RepositoryContext
from diagora.core.orchestrator import ScanOrchestrator
from diagora.core.registry import AnalyzerRegistry
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings

runner = CliRunner()


def test_cli_help_output() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == int(ExitCode.OK)
    assert "Diagora" in result.stdout
    assert "scan" in result.stdout
    assert "doctor" in result.stdout
    assert "report" in result.stdout
    assert "rules" in result.stdout


def test_cli_version_output() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == int(ExitCode.OK)
    assert f"diagora {__version__}" in result.stdout


def test_cli_scan_empty_repository(empty_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(empty_repo)])
    assert result.exit_code == int(ExitCode.OK)
    assert "Empty repository detected" in result.stdout
    assert "No diagnostic findings detected" in result.stdout


def test_cli_scan_json_format(python_node_repo: Path) -> None:
    result = runner.invoke(app, ["scan", str(python_node_repo), "--format", "json"])
    assert result.exit_code == int(ExitCode.OK)
    payload = json.loads(result.stdout)

    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["product_version"] == __version__
    repo = payload["repository"]
    assert repo["repository_name"] == "sample-app"
    assert repo["is_git_repository"] is True
    assert repo["is_empty"] is False
    assert set(repo["detected_ecosystems"]) == {
        "python",
        "node",
        "docker",
        "github_actions",
    }
    assert "uv" in repo["package_managers"]
    assert "pnpm" in repo["package_managers"]
    assert "pyproject.toml" in repo["manifests"]
    assert "package.json" in repo["manifests"]
    assert "Dockerfile" in repo["docker_files"]
    assert ".github/workflows/ci.yml" in repo["ci_workflows"]
    assert payload["summary"]["analyzers_executed"] == ["node", "python"]
    assert payload["summary"]["execution_status"] == "completed"


def test_cli_doctor_command(python_node_repo: Path) -> None:
    result = runner.invoke(app, ["doctor", str(python_node_repo)])
    assert result.exit_code == int(ExitCode.OK)
    assert "Diagora Doctor" in result.stdout
    assert "sample-app" in result.stdout


def test_cli_report_writes_json_file(python_node_repo: Path, tmp_path: Path) -> None:
    report_path = tmp_path / "output" / "report.json"
    result = runner.invoke(
        app,
        ["report", str(python_node_repo), "--output", str(report_path)],
    )
    assert result.exit_code == int(ExitCode.OK)
    assert report_path.exists()

    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["schema_version"] == SCHEMA_VERSION
    assert saved["repository"]["repository_name"] == "sample-app"


def test_cli_rules_list_terminal_and_json() -> None:
    term_res = runner.invoke(app, ["rules", "list"])
    assert term_res.exit_code == int(ExitCode.OK)
    assert "PY001" in term_res.stdout
    assert "ND001" in term_res.stdout
    assert "DK001" in term_res.stdout
    assert "ENV001" in term_res.stdout

    json_res = runner.invoke(
        app,
        ["rules", "list", "--category", "docker", "--format", "json"],
    )
    assert json_res.exit_code == int(ExitCode.OK)
    payload = json.loads(json_res.stdout)
    assert payload["total_rules"] == 10
    assert payload["implemented_rules"] == 0
    assert payload["deferred_rules"] == 10
    assert all(r["category"] == "docker" for r in payload["rules"])

    impl_res = runner.invoke(
        app,
        ["rules", "list", "--status", "implemented", "--format", "json"],
    )
    assert impl_res.exit_code == int(ExitCode.OK)
    impl_payload = json.loads(impl_res.stdout)
    assert impl_payload["total_rules"] == 19
    assert all(r["implemented"] is True for r in impl_payload["rules"])


def test_cli_invalid_and_nonexistent_repository_paths(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    res = runner.invoke(app, ["scan", str(missing)])
    assert res.exit_code == int(ExitCode.INVALID_USAGE)

    file_target = tmp_path / "just-a-file.txt"
    file_target.write_text("hello", encoding="utf-8")
    res_file = runner.invoke(app, ["scan", str(file_target)])
    assert res_file.exit_code == int(ExitCode.INVALID_USAGE)


def test_cli_invalid_arguments(empty_repo: Path) -> None:
    bad_fmt = runner.invoke(app, ["scan", str(empty_repo), "--format", "xml"])
    assert bad_fmt.exit_code == int(ExitCode.INVALID_USAGE)

    bad_sev = runner.invoke(app, ["scan", str(empty_repo), "--severity", "extreme"])
    assert bad_sev.exit_code == int(ExitCode.INVALID_USAGE)

    bad_cat = runner.invoke(app, ["rules", "list", "--category", "fortran"])
    assert bad_cat.exit_code == int(ExitCode.INVALID_USAGE)


def test_unsupported_project_files_reported_gracefully(unsupported_rust_repo: Path) -> None:
    res = runner.invoke(app, ["scan", str(unsupported_rust_repo), "--format", "json"])
    assert res.exit_code == int(ExitCode.OK)
    payload = json.loads(res.stdout)
    assert "Cargo.toml" in payload["repository"]["unsupported_files"]
    assert "go.mod" in payload["repository"]["unsupported_files"]
    assert payload["summary"]["analyzers_executed"] == []
    assert payload["summary"]["execution_status"] == "no_applicable_analyzers"
    assert any("unsupported ecosystems" in w for w in payload["warnings"])

    term_res = runner.invoke(app, ["scan", str(unsupported_rust_repo)])
    assert term_res.exit_code == int(ExitCode.OK)
    normalized_stdout = " ".join(term_res.stdout.split())
    assert "not a verified clean scan" in normalized_stdout


def test_mixed_monorepo_fixture_and_large_repo_handling(tmp_path: Path) -> None:
    mixed_fixture = Path(__file__).resolve().parents[1] / "fixtures" / "mixed" / "monorepo"
    res = runner.invoke(app, ["scan", str(mixed_fixture), "--format", "json"])
    assert res.exit_code == int(ExitCode.OK)
    payload = json.loads(res.stdout)
    assert payload["repository"]["is_monorepo"] is True
    assert set(payload["summary"]["analyzers_executed"]) == {"node", "python"}
    assert payload["summary"]["total_findings"] == 0

    # Large repository bounded by max_files_scanned
    large_repo = tmp_path / "large-repo"
    large_repo.mkdir()
    (large_repo / "pyproject.toml").write_text(
        '[project]\nname = "large"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n',
        encoding="utf-8",
    )
    src_dir = large_repo / "src"
    src_dir.mkdir()
    for i in range(60):
        (src_dir / f"mod_{i:03d}.py").write_text(f"VAL = {i}\n", encoding="utf-8")

    bounded = ScanOrchestrator(settings=ScanSettings(max_files_scanned=25)).scan(large_repo)
    assert bounded.repository.total_files_inspected == 25
    assert any("Maximum file scan limit" in w for w in bounded.warnings)


def test_monorepo_classification_ignores_nested_examples(tmp_path: Path) -> None:
    repo = tmp_path / "single-project-with-examples"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('[project]\nname = "root"\n', encoding="utf-8")
    ex_dir = repo / "examples" / "demo"
    ex_dir.mkdir(parents=True)
    (ex_dir / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")

    orchestrator = ScanOrchestrator()
    scan_res = orchestrator.scan(repo)
    assert scan_res.repository.is_monorepo is False
    assert [s.path for s in scan_res.repository.subprojects] == ["."]

    # Now add a real workspace package under packages/api
    pkg_dir = repo / "packages" / "api"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.json").write_text('{"name": "@app/api"}\n', encoding="utf-8")

    monorepo_res = orchestrator.scan(repo)
    assert monorepo_res.repository.is_monorepo is True
    assert [s.path for s in monorepo_res.repository.subprojects] == [".", "packages/api"]


def test_orchestrator_runs_registered_analyzers_and_correlates_issues(
    python_node_repo: Path,
) -> None:
    class MockDockerAnalyzer(BaseAnalyzer):
        name = "mock-docker"
        category = Category.DOCKER
        supported_ecosystems = (Ecosystem.DOCKER,)

        def analyze(
            self,
            repo_root: Path,
            context: RepositoryContext,
            settings: ScanSettings,
            rule_registry: RuleRegistry,
        ) -> list[Finding]:
            f1 = rule_registry.create_finding(
                finding_id="finding-001",
                rule_id="DK001",
                observed="backend/Dockerfile",
                expected="Existing Dockerfile",
                file="compose.yaml",
                line=4,
                confidence=Confidence.CONFIRMED,
                related_findings=["finding-002"],
            )
            f2 = rule_registry.create_finding(
                finding_id="finding-002",
                rule_id="DK002",
                observed="backend/",
                expected="Existing build context directory",
                file="compose.yaml",
                line=3,
                confidence=Confidence.CONFIRMED,
                related_findings=["finding-001"],
            )
            return [f1, f2]

    analyzer_reg = AnalyzerRegistry()
    analyzer_reg.register(MockDockerAnalyzer())
    settings = ScanSettings(fail_on_severity="high")  # type: ignore[arg-type]
    orchestrator = ScanOrchestrator(
        settings=settings,
        analyzer_registry=analyzer_reg,
    )
    result = orchestrator.scan(python_node_repo)

    assert result.summary.total_findings == 2
    assert result.summary.total_issues == 1
    assert result.summary.policy_passed is False
    assert result.issues[0].id == "issue-001"
    assert result.issues[0].related_finding_ids == ["finding-001", "finding-002"]
