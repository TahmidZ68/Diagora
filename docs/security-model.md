# Diagora Security & Threat Model

## 1. Local-First Threat Model

Because developers run `diagora` on newly cloned, unfamiliar, or potentially untrusted open-source repositories, Diagora treats every target repository as **untrusted input**.

| Threat Category | Attack Vector | Mitigation in Diagora |
| --------------- | ------------- | --------------------- |
| **Arbitrary Code Execution** | Malicious `setup.py`, npm scripts, Makefile hooks, or shell scripts inside the repository | Static scans never execute repository scripts, invoke compilers, or run package installs. `setup.py` is parsed via `ast.parse` only. |
| **Path Traversal** | Manifest references such as `../../etc/passwd` in `requirements.txt -r` or `tsconfig.json extends` | `validate_within_root()` and `validate_relative_finding_path()` canonicalize paths and enforce repository root containment. |
| **Symbolic-Link Attacks** | Symlinks inside the repo pointing to `/etc/shadow` or outside the workspace | `FileSystemRepositoryDiscoverer` skips symlinks and `safe_read_text()` rejects symlinks (`follow_symlinks=False`) or verifies containment. |
| **Parser DoS / Resource Exhaustion** | Giant files, deep directory trees, or deeply nested JSON/TOML/AST payloads | `ScanSettings` enforces `max_file_size_bytes` (5 MiB), `max_scan_depth` (15), `max_files_scanned` (10,000); parsers catch `RecursionError`. |
| **Secret Exposure** | API keys, database passwords, JWTs, or tokens embedded in `.env` or malformed manifests leaking into reports/errors | `redact_secrets()` and `redact_value()` scrub sensitive keys and token formats in `Evidence`, `Finding`, `DiagnosticIssue`, warnings, CLI errors, JSON, Markdown, and SARIF. |
| **Terminal / Markdown Injection** | Crafted manifest strings containing `[red]` Rich tags or `|` Markdown table delimiters | `TerminalRenderer` applies `rich.markup.escape()` and Markdown rendering escapes `|` and newlines. |
| **Command Injection (Runtime)** | Crafted filenames or config values passed to runtime subprocesses | Runtime probes are disabled by default; `validate_allowed_executable()` enforces an explicit allowlist (`ALLOWED_RUNTIME_EXECUTABLES`). |

---

## 2. Data Handling & Privacy

- **100% Offline Static Scanning**: Core diagnostic commands (`scan`, `doctor`, `report`, `rules list`) make zero outbound network calls.
- **No Source Uploads**: Repository contents are never transmitted to any backend or third-party AI service.
- **Minimal Path Exposure**: Findings store repository-relative POSIX paths only (`pyproject.toml`, `backend/uv.lock`), avoiding host filesystem path leakage.

---

## 3. Redaction Policy

Diagora scrubs sensitive data before persisting findings or rendering reports:

1. **Key-Based Redaction**: Keys matching sensitive identifiers (`secret`, `password`, `passwd`, `pwd`, `token`, `api_key`, `apikey`, `private_key`, `access_key`, `client_secret`, `auth_token`, `bearer`, `credential`, `connection_string`, `database_url`, `jwt_secret`, `signing_key`) have their values replaced with `"[REDACTED]"`.
2. **Pattern-Based Value Redaction**: Strings matching `ghp_...`/`github_pat_...`, `sk-...`, `AKIA...`/`ASIA...`, `AIza...`, `npm_...`, `pypi-...`, `xox...`, JWTs (`eyJ...`), `Bearer`/`Basic` auth headers, `-----BEGIN ... PRIVATE KEY-----` blocks, and URL userinfo credentials (`scheme://user:pass@host`) are scrubbed to `"[REDACTED]"`.

---

## 4. Known Limitations

- Heuristic pattern matching does not guarantee detection of unlabeled custom secret formats.
- Symlink-creation tests degrade to mocking `Path.is_symlink` when executed on Windows accounts lacking symlink privileges.
- Full runtime probing (M3) and explicit `--approve` file remediation (M5) are deferred in `0.1.0a2`.
