"""Unit tests for DockerAnalyzer (DK001-DK010)."""

from __future__ import annotations

from pathlib import Path

from diagora.core.orchestrator import ScanOrchestrator


def test_clean_docker_compose_and_dockerfile_passes_zero_findings(tmp_path: Path) -> None:
    repo = tmp_path / "clean-docker"
    repo.mkdir()
    (repo / ".dockerignore").write_text(".git\n.venv\n", encoding="utf-8")
    (repo / ".env.example").write_text("APP_ENV=prod\n", encoding="utf-8")
    (repo / "Dockerfile").write_text(
        "FROM python:3.12-slim\nEXPOSE 8000\nHEALTHCHECK CMD true\n",
        encoding="utf-8",
    )
    (repo / "compose.yaml").write_text(
        "services:\n"
        "  db:\n"
        "    image: postgres:16\n"
        "    healthcheck:\n"
        "      test: ['CMD', 'pg_isready']\n"
        "  api:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile\n"
        "    ports:\n"
        "      - '8080:8000'\n"
        "    env_file:\n"
        "      - path: .env.local\n"
        "        required: false\n"
        "    depends_on:\n"
        "      - db\n"
        "  migrate:\n"
        "    image: alpine:3.20\n",
        encoding="utf-8",
    )

    res = ScanOrchestrator().scan(repo)
    assert "docker" in res.summary.analyzers_executed
    docker_findings = [f for f in res.findings if f.category.value == "docker"]
    assert docker_findings == []


def test_docker_rules_dk001_dk002_dk004_dk005_dk006_dk007_dk008_dk009_dk010(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "broken-docker"
    repo.mkdir()
    app_dir = repo / "app"
    app_dir.mkdir()
    (app_dir / "Dockerfile").write_text("FROM node:20-alpine\nEXPOSE 3000\n", encoding="utf-8")

    (repo / "compose.yaml").write_text(
        "services:\n"
        "  api:\n"
        "    build:\n"
        "      context: ./app\n"
        "      dockerfile: Dockerfile\n"
        "    ports:\n"
        "      - '9000:9000'\n"
        "    env_file: .env.missing\n"
        "    depends_on:\n"
        "      - ghost_db\n"
        "    privileged: true\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
        "      - ./missing-data:/data\n"
        "  worker:\n"
        "    build:\n"
        "      context: ./app\n"
        "      dockerfile: Dockerfile.missing\n"
        "  escaped:\n"
        "    build: ../outside\n",
        encoding="utf-8",
    )

    res = ScanOrchestrator().scan(repo)
    rule_ids = {f.rule_id for f in res.findings}
    assert {
        "DK001",
        "DK002",
        "DK004",
        "DK005",
        "DK006",
        "DK007",
        "DK008",
        "DK009",
        "DK010",
    }.issubset(rule_ids)


def test_invalid_compose_yaml_triggers_dk003(tmp_path: Path) -> None:
    repo = tmp_path / "bad-compose"
    repo.mkdir()
    (repo / "compose.yaml").write_text("services:\n  web:\n    ports: [80\n", encoding="utf-8")

    res = ScanOrchestrator().scan(repo)
    dk003 = [f for f in res.findings if f.rule_id == "DK003"]
    assert len(dk003) == 1
    assert dk003[0].file == "compose.yaml"
