"""Unit tests for EnvironmentAnalyzer (ENV001-ENV006)."""

from __future__ import annotations

from pathlib import Path

from diagora.core.models import Severity
from diagora.core.orchestrator import ScanOrchestrator


def test_missing_env_example_triggers_env001(tmp_path: Path) -> None:
    repo = tmp_path / "env001-repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\nHEALTHCHECK CMD true\n", encoding="utf-8"
    )
    (repo / ".dockerignore").write_text(".git\n", encoding="utf-8")
    (repo / "compose.yaml").write_text(
        "services:\n  api:\n    build: .\n    environment:\n      DATABASE_URL: ${DATABASE_URL}\n",
        encoding="utf-8",
    )

    res = ScanOrchestrator().scan(repo)
    assert "environment" in res.summary.analyzers_executed
    env_rules = {f.rule_id for f in res.findings if f.category.value == "environment"}
    assert "ENV001" in env_rules


def test_env002_env003_env005_env006_and_false_positive_guards(tmp_path: Path) -> None:
    repo = tmp_path / "env-matrix-repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\nHEALTHCHECK CMD true\n", encoding="utf-8"
    )
    (repo / ".dockerignore").write_text(".git\n", encoding="utf-8")
    (repo / "app.py").write_text(
        'import os\nDB = os.environ["APP_PORT"]\nAPI = os.getenv("CODE_USED_VAR")\n',
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="0.1.0"\nrequires-python=">=3.12"\n',
        encoding="utf-8",
    )
    (repo / ".env.example").write_text(
        "APP_PORT=\n"
        "API_SECRET=\n"
        "CODE_USED_VAR=default\n"
        "LOG_LEVEL=info\n"
        "LOG_LEVEL=debug\n"
        "STALE_UNUSED_VAR=legacy\n",
        encoding="utf-8",
    )
    (repo / "compose.yaml").write_text(
        "services:\n"
        "  api:\n"
        "    build: .\n"
        "    environment:\n"
        "      APP_PORT: ${APP_PORT}\n"
        "      MISSING_FROM_EXAMPLE: ${MISSING_FROM_EXAMPLE}\n"
        "      PATH: ${PATH}\n"
        "      GITHUB_TOKEN: ${GITHUB_TOKEN}\n",
        encoding="utf-8",
    )

    res = ScanOrchestrator().scan(repo)
    env_findings = [f for f in res.findings if f.category.value == "environment"]
    by_rule: dict[str, list[str]] = {}
    for f in env_findings:
        by_rule.setdefault(f.rule_id, []).append(str(f.evidence.observed))

    # ENV002 fires for MISSING_FROM_EXAMPLE, NOT system PATH or GITHUB_TOKEN
    assert "ENV002" in by_rule
    assert any("MISSING_FROM_EXAMPLE" in obs for obs in by_rule["ENV002"])
    assert not any("PATH" in obs or "GITHUB_TOKEN" in obs for obs in by_rule["ENV002"])

    # ENV003 fires for blank non-secret APP_PORT, NOT blank secret API_SECRET in .env.example
    assert "ENV003" in by_rule
    assert any("APP_PORT" in obs for obs in by_rule["ENV003"])
    assert not any("API_SECRET" in obs for obs in by_rule["ENV003"])

    # ENV005 fires for duplicate/conflicting LOG_LEVEL
    assert "ENV005" in by_rule
    assert any("LOG_LEVEL" in obs for obs in by_rule["ENV005"])

    # ENV006 fires for STALE_UNUSED_VAR, NOT CODE_USED_VAR referenced in app.py
    assert "ENV006" in by_rule
    assert any("STALE_UNUSED_VAR" in obs for obs in by_rule["ENV006"])
    assert not any("CODE_USED_VAR" in obs for obs in by_rule["ENV006"])


def test_env004_committed_secret_detected_and_redacted(tmp_path: Path) -> None:
    repo = tmp_path / "env004-repo"
    repo.mkdir()
    fake_gh_token = "_".join(["ghp", "1234567890abcdefghijklmnopqrstuvwxyz"])
    (repo / ".env.example").write_text(f"GITHUB_ACCESS={fake_gh_token}\n", encoding="utf-8")
    (repo / ".env").write_text(
        "GITHUB_ACCESS=placeholder_ok\nDB_PASSWORD=superlivepass\n", encoding="utf-8"
    )

    res = ScanOrchestrator().scan(repo)
    env004 = [f for f in res.findings if f.rule_id == "ENV004"]
    assert len(env004) >= 2
    assert all(f.severity == Severity.CRITICAL for f in env004)
    serialized = str(res.model_dump())
    assert fake_gh_token not in serialized
    assert "superlivepass" not in serialized
