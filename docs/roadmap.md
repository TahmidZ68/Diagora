# Diagora Product Roadmap

## Milestone Sequence

| Milestone | Scope | Status |
| --------- | ----- | ------ |
| **M0 — Architecture & Foundation** | Scaffold, typed Pydantic models, security boundary, rule registry, discovery foundation, CLI (`scan`, `doctor`, `report`, `rules list`), JSON & Rich terminal reporting, test suite, CI workflow. | **Complete (v0.1.0a1)** |
| **M1 — Python & Node Discovery** | Full manifest parsers, lockfile consistency analyzers, monorepo workspace resolution, rule implementation status tracking, and deterministic rules `PY001`–`PY010` and `ND001`–`ND009` (`ND010` deferred to M3 runtime). | **Complete (v0.1.0a2)** |
| **M2 — Configuration & Docker** | Environment variable analyzer (`ENV001`–`ENV006`), YAML/JSON/TOML syntax validators, Dockerfile and Compose analyzers (`DK001`–`DK010`), deployment checks (`DP001`–`DP003`). | **Complete (v0.1.0a3)** |
| **M3 — Runtime Diagnostics** | Allowlisted subprocess runner, Python/Node interpreter version probes, package manager checks, Docker daemon/CLI probes, and local port availability checks. | Planned (v0.1.0b1) |
| **M4 — Root-Cause Engine** | Directed finding relationship graph, explicit cross-layer correlation rules, confidence scoring, duplicate recommendation suppression, and `DiagnosticIssue` synthesis. | Planned (v0.1.0b1) |
| **M5 — Remediation & Verification** | Rule-based remediation plans, unified diff previews, explicit `--approve` gate, backup/rollback store, and post-fix verification re-scans. | Planned (v0.1.0b2) |
| **M6 — Public Alpha** | Markdown and SARIF 2.1.0 exporters, golden test suite, GitHub Action composite action, PyPI release validation. | Planned (v0.1.0) |
