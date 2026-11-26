"""Unit and fixture tests for PythonAnalyzer (PY001-PY010)."""

from __future__ import annotations

from pathlib import Path

from diagora.core.models import Severity
from diagora.core.orchestrator import ScanOrchestrator

FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "python"


def _scan_rules(repo: Path) -> list[str]:
    result = ScanOrchestrator().scan(repo)
    return [f.rule_id for f in result.findings]


def test_valid_python_fixtures_produce_zero_findings() -> None:
    for name in ("valid-pip", "valid-poetry", "valid-uv"):
        res = ScanOrchestrator().scan(FIXTURES_ROOT / name)
        assert res.summary.execution_status == "completed"
        assert "python" in res.summary.analyzers_executed
        assert res.findings == [], f"Unexpected findings for {name}: {res.findings}"


def test_broken_pyproject_toml_triggers_py002_with_line() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "broken-pyproject")
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.rule_id == "PY002"
    assert finding.file == "pyproject.toml"
    assert finding.line == 2
    assert finding.severity == Severity.HIGH


def test_broken_deps_and_entrypoints_fixture() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "broken-deps-and-entrypoints")
    rule_ids = {f.rule_id for f in res.findings}
    assert "PY005" in rule_ids  # pydantic>=2.0.0 vs <2.0.0
    assert "PY006" in rule_ids  # missing [build-system] with scripts
    assert "PY007" in rule_ids  # requires-python = "python3.12"
    assert "PY009" in rule_ids  # invalid spec + missing -r + httpx cross-file conflict
    assert "PY010" in rule_ids  # missing entry point module


def test_missing_poetry_lock_triggers_py004() -> None:
    res = ScanOrchestrator().scan(FIXTURES_ROOT / "missing-poetry-lock")
    assert [f.rule_id for f in res.findings] == ["PY004"]
    assert res.findings[0].severity == Severity.LOW


def test_py001_missing_python_version_declaration(tmp_path: Path) -> None:
    repo = tmp_path / "py-no-ver"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "no-ver"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    assert "PY001" in _scan_rules(repo)


def test_py003_python_sources_without_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "py-no-manifest"
    repo.mkdir()
    (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")
    res = ScanOrchestrator().scan(repo)
    assert [f.rule_id for f in res.findings] == ["PY003"]
    assert res.findings[0].file == "main.py"


def test_py004_not_flagged_for_plain_pep621_or_pip_project(tmp_path: Path) -> None:
    repo = tmp_path / "plain-pep621"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n\n'
        '[project]\nname = "plain-lib"\nversion = "0.1.0"\nrequires-python = ">=3.10"\n'
        'dependencies = ["pydantic>=2.0"]\n',
        encoding="utf-8",
    )
    res = ScanOrchestrator().scan(repo)
    assert res.findings == []


def test_py008_missing_dev_group_when_tests_exist(tmp_path: Path) -> None:
    repo = tmp_path / "py-missing-dev"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10"\n',
        encoding="utf-8",
    )
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_ok.py").write_text("def test_x(): pass\n", encoding="utf-8")
    assert "PY008" in _scan_rules(repo)


def test_pipfile_and_pipfile_lock_consistency(tmp_path: Path) -> None:
    repo = tmp_path / "pipenv-proj"
    repo.mkdir()
    (repo / "Pipfile").write_text(
        '[requires]\npython_version = "3.12"\n\n[packages]\nrequests = "*"\nflask = "*"\n',
        encoding="utf-8",
    )
    (repo / "Pipfile.lock").write_text(
        '{"_meta": {}, "default": {"requests": {"version": "==2.31.0"}}, "develop": {}}',
        encoding="utf-8",
    )
    res = ScanOrchestrator().scan(repo)
    assert [f.rule_id for f in res.findings] == ["PY009"]
    assert "flask" in str(res.findings[0].evidence.observed)


def test_setup_cfg_and_setup_py_static_inspection(tmp_path: Path) -> None:
    repo = tmp_path / "legacy-setup"
    repo.mkdir()
    (repo / "setup.cfg").write_text(
        "[metadata]\nname = legacy\n\n[options]\npython_requires = bad-spec\n",
        encoding="utf-8",
    )
    (repo / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='legacy', entry_points={'console_scripts': ['cli = missing.mod:run']})\n",
        encoding="utf-8",
    )
    rule_ids = set(_scan_rules(repo))
    assert "PY007" in rule_ids
    assert "PY010" in rule_ids


def test_uv_lock_drift_detected(tmp_path: Path) -> None:
    repo = tmp_path / "uv-drift"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "uv-drift"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        'dependencies = ["fastapi>=0.110.0", "httpx>=0.27.0"]\n\n[tool.uv]\nmanaged = true\n',
        encoding="utf-8",
    )
    (repo / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "fastapi"\nversion = "0.111.0"\n',
        encoding="utf-8",
    )
    res = ScanOrchestrator().scan(repo)
    assert [f.rule_id for f in res.findings] == ["PY009"]
    assert "httpx" in str(res.findings[0].evidence.observed)
