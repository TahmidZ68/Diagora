"""Packaging and metadata consistency tests for Diagora distribution."""

from __future__ import annotations

import sys
from pathlib import Path

from diagora import __version__

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_pyproject_metadata_matches_package_version() -> None:
    pyproject_data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject_data["project"]

    assert project["name"] == "diagora-cli"
    assert project["version"] == __version__
    assert project["license"] == "Apache-2.0"
    assert project["readme"] == "README.md"
    assert project["requires-python"] == ">=3.10"
    assert project["scripts"] == {"diagora": "diagora.cli:main"}

    runtime_deps = " ".join(project["dependencies"]).lower()
    for dev_only in ("pytest", "mypy", "ruff", "build"):
        assert dev_only not in runtime_deps

    wheel_targets = pyproject_data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert wheel_targets == ["src/diagora"]


def test_required_root_open_source_files_exist() -> None:
    required = (
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "pyproject.toml",
        ".gitignore",
        ".editorconfig",
        ".gitattributes",
    )
    for filename in required:
        assert (REPO_ROOT / filename).is_file(), f"Missing required root file: {filename}"
