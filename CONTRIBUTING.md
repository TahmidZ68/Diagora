# Contributing to Diagora

Thank you for your interest in contributing to **Diagora** ("Find the cause. Verify the fix.").

## Core Architectural Principles

Before submitting a pull request, please ensure your changes adhere to Diagora's engineering principles:

1. **Deterministic Diagnostics First**: Every diagnostic finding must be backed by deterministic evidence and a registered rule definition.
2. **Read-Only by Default**: Analyzers must never modify files, install packages, or run arbitrary repository scripts.
3. **Security-First File Handling**: Always read repository files through `diagora.core.security` helpers to enforce path containment, symlink boundaries, file size limits, and secret redaction.
4. **Typed Data Models**: Use Pydantic models from `diagora.core.models` rather than unstructured dictionaries.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/TahmidZ68/Diagora.git
cd Diagora

# Create and activate a virtual environment
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

## Quality Gates

Every pull request must pass all local verification checks before merge:

```bash
# 1. Run test suite
pytest

# 2. Run linter and formatter checks
ruff check src tests

# 3. Run strict static type checking
mypy src

# 4. Verify reproducible package build
python -m build
```

## Adding a New Rule

1. Register the rule metadata in `src/diagora/rules/definitions/` with a stable ID (`PYxxx`, `NDxxx`, `ENVxxx`, `DKxxx`, `DPxxx`), version, default severity, category, evidence requirements, and remediation guidance.
2. Implement deterministic detection in the corresponding analyzer package under `src/diagora/analyzers/`.
3. Add unit tests for both positive and negative fixtures under `tests/unit/` and security boundary tests under `tests/security/`.
