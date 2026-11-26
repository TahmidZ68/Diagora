# Changelog

All notable changes to **Diagora** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0a2] - 2026-11-24

### Added
- **M1 — Python & Node.js Diagnostics Engine**:
  - Concrete static `PythonAnalyzer` implementing rules `PY001`–`PY010` across `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.cfg`, `setup.py` (AST-only static inspection), `.python-version`, and `runtime.txt`.
  - Concrete static `NodeAnalyzer` implementing rules `ND001`–`ND009` across `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `pnpm-workspace.yaml`, `.npmrc`, `.nvmrc`, `.node-version`, and `tsconfig.json` (JSONC-aware).
  - Default `build_default_analyzer_registry()` wired into `ScanOrchestrator`.
  - Rule implementation status tracking (`implemented` vs. `deferred`) in `RuleDefinition`, `diagora rules list --status`, and JSON/terminal outputs.
  - Scan execution tracking (`analyzers_executed`, `execution_status = "no_applicable_analyzers"`) so repositories without applicable analyzers are never misreported as verified clean scans.
  - Workspace-aware subproject classification supporting monorepos, nested projects, and workspace child inheritance without duplicate or false-positive lockfile findings.
  - Representative Python, Node.js, mixed monorepo, nested project, and large repository fixtures plus golden output tests.
  - Security & production hardening: extended secret redaction (`AIza`, `npm_`, `pypi-`, JWT, Basic auth), parser recursion-depth protection (`RecursionError` guards for JSON, TOML, YAML, and AST), Rich markup & Markdown table escaping, CLI error redaction, and Unicode/packaging test coverage.
  - Open-source repository & CI readiness: `CODE_OF_CONDUCT.md`, `.editorconfig`, `.gitattributes`, GitHub issue/PR templates, Dependabot config, SHA-pinned CI workflow with clean wheel smoke tests, and `pip-audit` dependency security workflow.
  - Release notes in `docs/releases/v0.1.0a2.md`.

## [0.1.0a1] - 2026-11-24

### Added
- **Phase 0 Foundation Architecture**:
  - Modular package layout (`core`, `analyzers`, `runtime`, `diagnosis`, `remediation`, `reporting`, `integrations`, `rules`).
  - Strongly typed Pydantic v2 models (`Finding`, `Evidence`, `DiagnosticIssue`, `ScanResult`, `RepositoryContext`, `RuleDefinition`) with versioned JSON schema envelope (`1.0.0`).
  - Central rule registry with initial catalog of Python (`PY001`–`PY010`), Node.js (`ND001`–`ND010`), Environment (`ENV001`–`ENV006`), Docker (`DK001`–`DK010`), and Deployment (`DP001`–`DP003`) rule specifications.
  - Repository discovery and project classification engine supporting Python, Node.js, Docker, environment, deployment, and monorepo structures.
  - Security boundary layer enforcing repository path containment, symlink escape prevention, file size and depth limits, and deterministic secret redaction.
  - Scan orchestrator and analyzer interface with pluggable analyzer registry.
  - Typer CLI supporting `diagora --help`, `diagora --version`, `diagora scan`, `diagora doctor`, `diagora report`, and `diagora rules list`.
  - Rich terminal renderer and versioned JSON report serializer.
