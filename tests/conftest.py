"""Shared pytest fixtures creating isolated temporary repositories for testing."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def empty_repo(tmp_path: Path) -> Path:
    """Return an empty temporary repository directory."""
    repo = tmp_path / "empty-repo"
    repo.mkdir()
    return repo


@pytest.fixture()
def python_node_repo(tmp_path: Path) -> Path:
    """Return a mixed Python + Node.js + Docker temporary repository fixture."""
    repo = tmp_path / "sample-app"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "0.1.0"\nrequires-python = ">=3.10"\n',
        encoding="utf-8",
    )
    (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (repo / "package.json").write_text(
        '{"name": "sample-web", "version": "1.0.0"}\n',
        encoding="utf-8",
    )
    (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (repo / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (repo / "compose.yaml").write_text("services:\n  api:\n    build: .\n", encoding="utf-8")
    (repo / ".env.example").write_text("APP_ENV=development\n", encoding="utf-8")
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: CI\non: [push]\n", encoding="utf-8")
    return repo


@pytest.fixture()
def unsupported_rust_repo(tmp_path: Path) -> Path:
    """Return a repository containing only unsupported ecosystem manifests (Rust/Go)."""
    repo = tmp_path / "rust-service"
    repo.mkdir()
    (repo / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (repo / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    return repo
