# Diagora

> **Developer diagnostics and root-cause intelligence**  
> **Find the cause. Verify the fix.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version: 0.1.0a2](https://img.shields.io/badge/version-0.1.0a2-informational.svg)](CHANGELOG.md)

---

## The Problem

When developers clone an unfamiliar repository, onboard onto a multi-service project, or debug broken CI setups, failures rarely stay confined to a single file. Dependency constraints drift from lockfiles, Python/Node.js runtime expectations conflict across manifests, and workspaces break silently—often requiring multiple ad-hoc checks before the underlying cause is clear.

## What Diagora Does

**Diagora** (`diagora-cli`) is an open-source, **local-first**, **read-only-by-default** repository diagnostics CLI. It inspects project structure, dependency manifests, lockfiles, and workspace configurations and emits deterministic, evidence-backed findings (`observed` vs. `expected`) across Terminal, JSON, Markdown, and SARIF 2.1.0 outputs—without requiring an API key, hosted backend, or outbound network access.

## What Makes Diagora Different

Diagora is engineered around a three-stage diagnostic model:

1. **Deterministic static diagnostics first** — repeatable, schema-validated findings backed by file/line evidence.
2. **Optional opt-in runtime probes second** *(planned)* — isolated behind explicit `--runtime` flags and an executable allowlist.
3. **Cross-layer root-cause correlation third** *(in progress; core graph foundation built, cross-layer correlation rules planned)* — designed to connect related failures across dependencies, configuration, Docker, deployment, and runtime rather than emitting isolated, context-free warnings.

> **Transparency note:** In `v0.1.0a2` (Milestone M1), concrete static analyzers are implemented for **Python** (`PY001`–`PY010`) and **Node.js** (`ND001`–`ND009`). Environment, Docker, Deployment, Runtime, Cross-Layer Correlation Rules, and `--approve` Remediation are deferred to upcoming milestones and are clearly labeled below.

---

## Key Capabilities (`v0.1.0a2`)

- **Repository & Monorepo Discovery**: Detects Python, Node.js, mixed Python+Node repositories, monorepo subprojects, and workspaces while avoiding false subprojects inside `examples/`, `docs/`, or `tests/fixtures/`.
- **Python Static Diagnostics (`PY001`–`PY010`)**: Parses `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.cfg`, `setup.py` (via safe `ast.parse`, never executed), `.python-version`, and `runtime.txt`.
- **Node.js Static Diagnostics (`ND001`–`ND009`)**: Parses `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 & Berry), `pnpm-workspace.yaml`, `.npmrc`, `.nvmrc`, `.node-version`, and `tsconfig.json` (JSONC-aware).
- **Honest Execution Tracking**: Reports `analyzers_executed` and `execution_status` (`completed` vs. `no_applicable_analyzers`) so unsupported repositories are never falsely reported as verified clean scans.
- **Multi-Format Reporting**: Rich terminal tables, versioned JSON (`schema_version: "1.0.0"`), GitHub-Flavored Markdown, and SARIF 2.1.0.

---

## Supported Ecosystems

| Ecosystem | Current Status (`v0.1.0a2`) | Files Inspected |
| --------- | --------------------------- | --------------- |
| **Python** | **Implemented** (`PY001`–`PY010`) | `pyproject.toml`, `requirements*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.cfg`, `setup.py` (AST), `.python-version`, `runtime.txt` |
| **Node.js / TypeScript** | **Implemented** (`ND001`–`ND009`) | `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `pnpm-workspace.yaml`, `.npmrc`, `.nvmrc`, `.node-version`, `tsconfig.json` |
| **Docker / Compose** | Discovery only (**Deferred** to M2) | `Dockerfile`, `compose.yaml`, `docker-compose.yml`, `.dockerignore` |
| **Environment** | Discovery only (**Deferred** to M2) | `.env.example`, `.env.sample`, `.gitignore` |
| **Deployment / CI** | Discovery only (**Deferred** to M2) | `.github/workflows/*.yml`, `vercel.json`, generic manifests |

---

## Installation

### From Source (Local Clone)

Requires **Python 3.10+**.

```bash
git clone https://github.com/TahmidZ68/Diagora.git
cd Diagora

python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -e .
```

Or install from a built wheel:

```bash
pip install dist/diagora_cli-0.1.0a2-py3-none-any.whl
```

---

## Quick Start

```bash
diagora --version
diagora --help
diagora scan .
diagora doctor .
diagora rules list
diagora rules list --status implemented
```

---

## CLI Examples

```bash
# Scan a repository with Rich terminal output
diagora scan ./my-project

# Emit versioned JSON to stdout
diagora scan ./my-project --format json

# Fail CI (exit code 1) if any HIGH or CRITICAL findings exist
diagora scan ./my-project --severity high

# Generate a SARIF 2.1.0 file for code scanning
diagora report ./my-project --output report.sarif

# Generate a Markdown diagnostic report
diagora report ./my-project --output report.md

# Filter registered rules by category or implementation status
diagora rules list --category python
diagora rules list --status implemented
```

### CLI Exit Codes

| Exit Code | Meaning |
| --------- | ------- |
| `0` | Scan completed without policy threshold breaches |
| `1` | Findings breached the configured `--severity` threshold |
| `2` | Invalid CLI arguments, nonexistent path, or configuration error |
| `3` | Diagnostic execution error (e.g., permission denied, path security violation) |
| `4` | Unsupported scan mode |

---

## Example Terminal Output

```text
╭────────────────── Diagora Scan v0.1.0a2 ───────────────────╮
│ Repository: broken-node-project (.)                        │
│ Git Repository: no  Monorepo: no  Files Inspected: 4       │
│ Ecosystems: node  Package Managers: npm, yarn              │
│ Analyzers Executed: node  Status: completed                │
╰──────────────────────────────────────────────────────────────╯
```

When scanning a repository where no implemented analyzer applies (e.g., Rust/Go-only):

```text
No applicable static analyzer executed for this repository (not a verified clean scan).
```

---

## JSON & SARIF Reporting Examples

### Versioned JSON Envelope (`schema_version: "1.0.0"`)

```json
{
  "schema_version": "1.0.0",
  "product_name": "diagora",
  "product_version": "0.1.0a2",
  "repository": {
    "repository_name": "monorepo",
    "is_monorepo": true,
    "detected_ecosystems": ["docker", "node", "python"],
    "package_managers": ["npm", "uv"]
  },
  "findings": [],
  "issues": [],
  "summary": {
    "total_findings": 0,
    "total_issues": 0,
    "analyzers_executed": ["node", "python"],
    "policy_passed": true,
    "execution_status": "completed"
  }
}
```

### SARIF 2.1.0 Output

Run `diagora scan . --format sarif` or `diagora report . --output report.sarif` to produce a SARIF `2.1.0` envelope (`runs[0].tool.driver.name = "Diagora"`) mapping `CRITICAL`/`HIGH` to `error`, `MEDIUM` to `warning`, and `LOW`/`INFORMATIONAL` to `note`, with repository-relative `artifactLocation.uri` and `startLine` regions.

---

## Supported Rule Catalog

Diagora registers **39 rules** (`19 implemented`, `20 deferred`). Run `diagora rules list` for live status.

### Implemented Rules (`19`)

- **Python (`PY001`–`PY010`)**: `PY001` Missing Python version declaration, `PY002` Invalid `pyproject.toml` / manifest, `PY003` Missing dependency manifest, `PY004` Missing expected lockfile (Poetry/uv/Pipenv), `PY005` Conflicting dependency declarations, `PY006` Missing `[build-system]` on distributable packages, `PY007` Invalid Python version constraint, `PY008` Missing dev dependency group, `PY009` Inconsistent requirements files / lockfile drift, `PY010` Missing package entry point reference.
- **Node.js (`ND001`–`ND009`)**: `ND001` Invalid `package.json`, `ND002` Missing Corepack `packageManager`, `ND003` Multiple conflicting lockfiles / manager mismatch, `ND004` Missing/mismatched Node.js engine requirement, `ND005` Invalid script configuration, `ND006` Missing referenced entry point, `ND007` Workspace configuration inconsistency, `ND008` TypeScript configuration inconsistency, `ND009` Lockfile/package manifest mismatch.

### Deferred Rules (`20`)

- **Node.js Runtime (`ND010`)**: Runtime package manager availability (M3).
- **Environment (`ENV001`–`ENV006`)**: Environment template and secret hygiene rules (M2).
- **Docker (`DK001`–`DK010`)**: Dockerfile and Compose static rules (M2).
- **Deployment (`DP001`–`DP003`)**: GitHub Actions and `vercel.json` rules (M2).

See [Diagnostic Rules Catalog](docs/rules.md) for full details.

---

## Implemented vs. Planned Functionality

| Capability | Status |
| ---------- | ------ |
| Core Pydantic v2 models, rule registry, CLI (`scan`, `doctor`, `report`, `rules list`) | **Implemented** |
| Security boundaries (path containment, symlink guard, size/depth limits, secret redaction) | **Implemented** |
| Python & Node.js static analyzers (`PY001`–`PY010`, `ND001`–`ND009`) | **Implemented** |
| Terminal, JSON, Markdown, and SARIF 2.1.0 reporting | **Implemented** |
| Finding normalizer & explicit `related_findings` grouping foundation | **Implemented** *(cross-layer rules planned)* |
| Environment, Docker, and Deployment static analyzers (`ENV`, `DK`, `DP`) | **Planned (M2)** |
| Opt-in runtime probes (`--runtime` / `ND010`) | **Planned (M3)** *(allowlist scaffolded)* |
| Cross-layer root-cause correlation graph | **Planned (M4)** |
| Rule-based remediation previews, `--approve`, backup & verification | **Planned (M5)** *(safety guards scaffolded)* |
| Optional AI explanation adapter | **Deferred** *(never required)* |

---

## Security & Privacy

Diagora treats scanned repositories as untrusted input:

- **Read-only & offline static scans** — zero repository script execution, zero package installs, zero network calls.
- **Path & symlink containment** — blocks `../` traversal and symlink escapes outside the repository root.
- **Resource bounds** — caps max file size (5 MiB), scan depth (15), total scanned files (10,000), and parser recursion.
- **Automatic secret redaction** — scrubs API keys, tokens, passwords, connection strings, JWTs, and private keys before rendering or serializing.

See [SECURITY.md](SECURITY.md) and [Security & Threat Model](docs/security-model.md).

---

## Architecture Overview

```text
CLI (diagora.cli)
  └─▶ ScanOrchestrator (diagora.core.orchestrator)
        ├─▶ FileSystemRepositoryDiscoverer (boundary & symlink safe)
        ├─▶ ProjectClassifier (Python, Node.js, monorepo, workspaces)
        ├─▶ AnalyzerRegistry ─▶ PythonAnalyzer (PY001–PY010), NodeAnalyzer (ND001–ND009)
        ├─▶ FindingNormalizer (deduplication & deterministic ordering)
        ├─▶ FindingCorrelator (DiagnosticIssue synthesis)
        └─▶ Reporting (Terminal / JSON / Markdown / SARIF 2.1.0)
```

See [Architecture Specification](docs/architecture.md).

---

## Development Setup & Running Tests

```bash
pip install -e ".[dev]"

# Linting & formatting
ruff format --check src tests
ruff check src tests

# Strict type checking
mypy src

# Full test suite (unit, integration, security, golden snapshots)
pytest -v

# Build sdist and wheel
python -m build
```

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

---

## Roadmap

- **M0 (v0.1.0a1):** Core foundation, models, security boundaries, CLI, reporting — **Complete**
- **M1 (v0.1.0a2):** Python & Node.js static analyzers (`PY001`–`PY010`, `ND001`–`ND009`) — **Complete**
- **M2 (v0.1.0a3):** Environment, Docker, and Deployment static analyzers — **Planned**
- **M3 (v0.1.0b1):** Opt-in runtime probes — **Planned**
- **M4 (v0.1.0b1):** Cross-layer root-cause correlation engine — **Planned**
- **M5 (v0.1.0b2):** Remediation patch previews, `--approve`, backup & verification — **Planned**
- **M6 (v0.1.0):** Public Alpha release validation — **Planned**

See [Product Roadmap](docs/roadmap.md) and [v0.1.0a2 Release Notes](docs/releases/v0.1.0a2.md).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
