# Security Policy

## Local-First Design & Data Handling

**Diagora** is architected as a **local-first, read-only-by-default** diagnostic CLI. Because developers frequently run diagnostics on unfamiliar or untrusted repositories, Diagora treats every target repository and configuration file as untrusted input:

- **Zero Telemetry or Uploads**: Static scans perform no outbound network requests and never upload repository files, manifests, or diagnostic reports.
- **No Arbitrary Code Execution**: Static scans (`diagora scan`, `diagora doctor`, `diagora report`) never execute repository shell scripts, `setup.py`, npm lifecycle hooks, Docker builds, or package installation commands. `setup.py` is inspected strictly via static AST parsing (`ast.parse`).
- **Safe Structured Parsing**: TOML (`tomllib`/`tomli`), JSON/JSONC (`json.loads`), INI (`ConfigParser(interpolation=None)`), and YAML (`yaml.safe_load`) parsers run safely and guard against `RecursionError` from deeply nested adversarial payloads.

## Supported Security Boundaries

1. **Repository Boundary Containment**: All discovered and read paths are canonicalized and verified via `validate_within_root()` to reside strictly within the resolved repository root. Path traversal payloads (`../`, encoded segments) raise `PathSecurityError`.
2. **Symlink Containment**: Symbolic links are skipped during repository discovery and rejected during file reads by default (`follow_symlinks=False`), preventing symlink escape attacks.
3. **Resource Exhaustion Safeguards**: `ScanSettings` enforces bounded file reads (`max_file_size_bytes`, default 5 MiB), directory traversal depth (`max_scan_depth`, default 15), and total scanned files (`max_files_scanned`, default 10,000).
4. **Secret Redaction**: Evidence fields, findings, warnings, CLI error messages, terminal output, and serialized JSON/Markdown/SARIF reports automatically pass through `diagora.core.security` redaction (`[REDACTED]`), scrubbing sensitive keys (`API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE_KEY`, `DATABASE_URL` credentials) and common token patterns (GitHub PATs, AWS keys, Google API keys, npm/PyPI tokens, JWTs, Bearer/Basic headers, and PEM private keys).
5. **Output Escaping & Safe Report Writes**: Terminal output escapes Rich markup tags and Markdown reports escape table delimiters. `--output` rejects symbolic links and existing directories.
6. **Runtime Probe Isolation (Deferred / Opt-In)**: Runtime checks are disabled by default; when implemented in M3, subprocess execution will remain gated behind explicit `--runtime` opt-in and `ALLOWED_RUNTIME_EXECUTABLES`.

## Known Security Limitations

- Secret redaction relies on key-name heuristics and known token patterns; arbitrary high-entropy strings without recognizable prefixes or sensitive key context may not be redacted.
- `diagora` treats the local user running the CLI as trusted with respect to `--output` file paths chosen by that user.
- On hosts without OS symlink creation privileges, symlink tests fall back to mocking `Path.is_symlink`.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` (Alpha) | Security fixes on latest pre-release |

## Reporting a Vulnerability

If you discover a security vulnerability in Diagora—especially path boundary bypasses, parser crashes/DoS, secret leakage in reports, or unintended command execution—please report it privately rather than opening a public issue:

1. Use the repository's **GitHub Security Advisories** ("Report a vulnerability" under the **Security** tab) to submit a confidential report.
2. Include the output of `diagora --version`, a minimal reproduction fixture, and the exact command invoked.
3. Maintainers will review the report via the private advisory thread before any public disclosure or patch release.
