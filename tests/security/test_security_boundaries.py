"""Security tests for path traversal, symlinks, file caps, permissions, and secret redaction."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from diagora.cli import app
from diagora.core.exceptions import (
    ExitCode,
    PathSecurityError,
    RepositoryPermissionError,
    ResourceLimitExceededError,
)
from diagora.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    RepositoryContext,
    ScanResult,
    ScanSummary,
    Severity,
)
from diagora.core.orchestrator import ScanOrchestrator
from diagora.core.security import (
    REDACTED_PLACEHOLDER,
    redact_secrets,
    redact_value,
    safe_read_text,
    to_relative_posix_path,
    validate_repository_root,
    validate_within_root,
)
from diagora.reporting.json import serialize_scan_result
from diagora.reporting.markdown import serialize_markdown_report
from diagora.reporting.sarif import serialize_sarif_report
from diagora.reporting.terminal import TerminalRenderer
from diagora.runtime.process_runner import validate_allowed_executable
from diagora.settings import ScanSettings

runner = CliRunner()


@pytest.mark.parametrize(
    "traversal_target",
    [
        "../outside.txt",
        "../../etc/passwd",
        "subdir/../../../outside.env",
        "a/b/../../../../secret.key",
    ],
)
def test_path_traversal_attempts_blocked(tmp_path: Path, traversal_target: str) -> None:
    repo = tmp_path / "secure-repo"
    repo.mkdir()

    with pytest.raises(PathSecurityError):
        validate_within_root(traversal_target, repo)

    with pytest.raises(PathSecurityError):
        to_relative_posix_path(traversal_target, repo)

    with pytest.raises(PathSecurityError):
        safe_read_text(traversal_target, repo)


def test_outside_absolute_path_blocked(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    outside = tmp_path / "repo-b"
    repo.mkdir()
    outside.mkdir()
    outside_file = outside / "secret.txt"
    outside_file.write_text("top-secret", encoding="utf-8")

    with pytest.raises(PathSecurityError):
        validate_within_root(outside_file, repo)


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo-with-symlink"
    repo.mkdir()
    outside_file = tmp_path / "outside-secret.txt"
    outside_file.write_text("SECRET_TOKEN=ghp_1234567890abcdefghijklmnop", encoding="utf-8")

    link_path = repo / "escaped_link.txt"
    created_real_symlink = False
    try:
        os.symlink(outside_file, link_path)
        created_real_symlink = True
    except (OSError, NotImplementedError) as exc:
        if os.name != "nt":
            pytest.fail(f"Real symlink creation must succeed on POSIX hosts: {exc}")
        link_path.write_text("placeholder", encoding="utf-8")

    if created_real_symlink:
        with pytest.raises(PathSecurityError):
            safe_read_text(link_path, repo, follow_symlinks=False)

        with pytest.raises(PathSecurityError):
            validate_within_root(link_path, repo, follow_symlinks=True)

        result = ScanOrchestrator().scan(repo)
        assert "escaped_link.txt" not in result.repository.discovered_files
        assert any("Skipped symbolic link" in w for w in result.warnings)
    else:
        orig_is_symlink = Path.is_symlink

        def _fake_is_symlink(self: Path) -> bool:
            if self.name == "escaped_link.txt":
                return True
            return orig_is_symlink(self)

        with (
            patch.object(Path, "is_symlink", _fake_is_symlink),
            pytest.raises(PathSecurityError),
        ):
            safe_read_text(link_path, repo, follow_symlinks=False)


@pytest.mark.skipif(
    os.name == "nt",
    reason="Linux/POSIX real-symlink test; Windows symlink fallback covered above.",
)
def test_posix_real_symlink_directory_and_file_containment(tmp_path: Path) -> None:
    repo = tmp_path / "posix-symlink-repo"
    outside_dir = tmp_path / "outside-dir"
    repo.mkdir()
    outside_dir.mkdir()
    (outside_dir / "pyproject.toml").write_text('[project]\nname="outside"\n', encoding="utf-8")

    dir_link = repo / "linked_dir"
    os.symlink(outside_dir, dir_link, target_is_directory=True)

    with pytest.raises(PathSecurityError):
        validate_within_root("linked_dir/pyproject.toml", repo, follow_symlinks=False)
    with pytest.raises(PathSecurityError):
        validate_within_root("linked_dir/pyproject.toml", repo, follow_symlinks=True)

    result = ScanOrchestrator().scan(repo)
    assert result.repository.manifests == []
    assert any("Skipped symbolic link 'linked_dir'" in w for w in result.warnings)


def test_oversized_file_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "large-file-repo"
    repo.mkdir()
    big_file = repo / "huge.json"
    big_file.write_bytes(b"x" * 4096)

    with pytest.raises(ResourceLimitExceededError):
        safe_read_text(big_file, repo, max_bytes=1024)


def test_max_files_and_depth_limits_enforced(tmp_path: Path) -> None:
    repo = tmp_path / "deep-repo"
    repo.mkdir()
    deep_dir = repo / "d1" / "d2" / "d3" / "d4"
    deep_dir.mkdir(parents=True)
    (deep_dir / "pyproject.toml").write_text('[project]\nname="deep"\n', encoding="utf-8")

    settings = ScanSettings(max_scan_depth=2)
    orchestrator = ScanOrchestrator(settings=settings)
    result = orchestrator.scan(repo)
    assert result.repository.manifests == []
    assert any("Maximum scan depth" in w for w in result.warnings)


def test_permission_errors_handled_gracefully(tmp_path: Path) -> None:
    repo = tmp_path / "locked-repo"
    repo.mkdir()

    with patch("diagora.core.security.os.scandir", side_effect=PermissionError("Access denied")):
        with pytest.raises(RepositoryPermissionError):
            validate_repository_root(repo)

        cli_res = runner.invoke(app, ["scan", str(repo)])
        assert cli_res.exit_code == int(ExitCode.EXECUTION_ERROR)
        assert "REPOSITORY_PERMISSION_ERROR" in (cli_res.stdout + cli_res.stderr)


def test_secret_redaction_across_strings_and_models() -> None:
    slack_token = "-".join(["xoxb", "123456789012", "1234567890123", "abcdefABCDEF123456"])
    raw_samples = [
        "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "OPENAI_API_KEY: 'sk-proj-1234567890abcdefghijklmnop'",
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload",
        "postgres://admin:SuperSecretPass123!@db.internal:5432/prod",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        f"SLACK_TOKEN={slack_token}",
    ]

    for sample in raw_samples:
        redacted = redact_secrets(sample)
        assert REDACTED_PLACEHOLDER in redacted
        assert "ghp_1234567890" not in redacted
        assert "sk-proj-1234567890" not in redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "SuperSecretPass123!" not in redacted
        assert "MIIEowIBAAKCAQEA" not in redacted
        assert slack_token[:17] not in redacted

    # Verify dictionary key-based redaction and Evidence auto-redaction
    evidence = Evidence(
        observed={
            "DATABASE_PASSWORD": "my_plaintext_db_password",
            "api_secret": "ultra_secret_value",
            "PORT": "8080",
        },
        expected="Redacted configuration",
    )
    assert evidence.observed["DATABASE_PASSWORD"] == REDACTED_PLACEHOLDER
    assert evidence.observed["api_secret"] == REDACTED_PLACEHOLDER
    assert evidence.observed["PORT"] == "8080"

    finding = Finding(
        id="finding-sec-1",
        rule_id="ENV004",
        title="Exposed secret API_KEY=my_live_key_value_999",
        description="Found token ghp_1234567890abcdefghijklmnopqrstuvwxyz in file.",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category=Category.ENVIRONMENT,
        file=".env.example",
        evidence=evidence,
        recommendation="Remove API_KEY=my_live_key_value_999 immediately.",
    )
    assert "my_live_key_value_999" not in finding.title
    assert "ghp_1234567890" not in finding.description
    assert "my_live_key_value_999" not in finding.recommendation
    assert REDACTED_PLACEHOLDER in redact_value(finding.model_dump())["description"]


def test_runtime_executable_allowlist_blocks_arbitrary_binaries() -> None:
    assert validate_allowed_executable("python") == "python"
    assert validate_allowed_executable("docker") == "docker"

    for forbidden in ["bash", "sh", "powershell", "cmd.exe", "curl", "rm", "./setup.sh"]:
        with pytest.raises(PathSecurityError):
            validate_allowed_executable(forbidden)


def test_malicious_setup_py_is_never_executed(tmp_path: Path) -> None:
    repo = tmp_path / "evil-setup"
    repo.mkdir()
    marker_file = tmp_path / "pwned.txt"
    (repo / "setup.py").write_text(
        f"from pathlib import Path\n"
        f"Path({str(marker_file)!r}).write_text('executed')\n"
        f"raise RuntimeError('should never execute')\n",
        encoding="utf-8",
    )

    result = ScanOrchestrator().scan(repo)
    assert not marker_file.exists()
    assert result.summary.execution_status == "completed"


def test_traversal_in_requirements_include_and_tsconfig_extends_blocked(tmp_path: Path) -> None:
    repo = tmp_path / "traversal-manifests"
    repo.mkdir()
    (repo / "requirements.txt").write_text("-r ../../etc/passwd\n", encoding="utf-8")
    (repo / "package.json").write_text(
        '{"name": "trv", "packageManager": "npm@10.0.0", "engines": {"node": ">=20"}}\n',
        encoding="utf-8",
    )
    (repo / "tsconfig.json").write_text(
        '{"extends": "../../../outside.json"}\n',
        encoding="utf-8",
    )

    result = ScanOrchestrator().scan(repo)
    rule_ids = {f.rule_id for f in result.findings}
    assert "PY009" in rule_ids
    assert "ND008" in rule_ids
    observed_text = " ".join(str(f.evidence.observed) for f in result.findings)
    assert "../../etc/passwd" in observed_text
    assert "escapes" in observed_text


def test_secret_redacted_inside_malformed_manifest_findings(tmp_path: Path) -> None:
    repo = tmp_path / "secret-in-req"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        "TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n",
        encoding="utf-8",
    )
    result = ScanOrchestrator().scan(repo)
    assert result.findings
    serialized = str(result.model_dump())
    assert "ghp_1234567890" not in serialized
    assert REDACTED_PLACEHOLDER in serialized


def test_extended_token_patterns_redacted() -> None:
    samples = [
        "GOOGLE_KEY=AIzaSyDummyKeyValue1234567890abcdefghijk",
        "NPM_TOKEN=npm_1234567890abcdefghijklmnop",
        "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4OTA",
        "JWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature12345",
        "Authorization: Basic dXNlcjpzdXBlcnNlY3JldA==",
    ]
    for raw in samples:
        redacted = redact_secrets(raw)
        assert REDACTED_PLACEHOLDER in redacted
        assert "AIzaSyDummy" not in redacted
        assert "npm_1234567890" not in redacted
        assert "pypi-AgEIcHlwa" not in redacted
        assert "signature12345" not in redacted
        assert "dXNlcjpzdXBlcnNlY3JldA" not in redacted


def test_deeply_nested_adversarial_manifests_handled_safely(tmp_path: Path) -> None:
    repo = tmp_path / "nested-dos"
    repo.mkdir()
    # Deeply nested JSON (exceeds Python default recursion limit)
    (repo / "package.json").write_text("[" * 1500 + "]" * 1500, encoding="utf-8")
    # Deeply nested TOML array
    (repo / "pyproject.toml").write_text("a = " + "[" * 1500 + "]" * 1500, encoding="utf-8")

    result = ScanOrchestrator().scan(repo)
    rule_ids = {f.rule_id for f in result.findings}
    assert "ND001" in rule_ids
    assert "PY002" in rule_ids


def test_basic_auth_redaction_variations_and_negative_cases() -> None:
    positive_cases = [
        ("Authorization: Basic dXNlcjpzdXBlcnNlY3JldA==", "dXNlcjpzdXBlcnNlY3JldA=="),
        ("authorization: basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("AUTHORIZATION:   BASIC    YWRtaW46cGFzc3dvcmQxMjM=", "YWRtaW46cGFzc3dvcmQxMjM="),
        ("Proxy-Authorization: Basic dXNlcjpwYXNz==", "dXNlcjpwYXNz=="),
        ("Header Basic\tdXNlcjpzdXBlcnNlY3JldA==", "dXNlcjpzdXBlcnNlY3JldA=="),
    ]
    for raw, secret in positive_cases:
        redacted = redact_secrets(raw)
        assert REDACTED_PLACEHOLDER in redacted
        assert secret not in redacted
        # Ensure base64 was not decoded to expose plaintext user:pass
        assert "supersecret" not in redacted
        assert "user:pass" not in redacted

    negative_cases = [
        "SGVsbG8gV29ybGQh",
        "dGhpcyBpcyBhIHRlc3Q=",
        "Basic configuration",
        "Basic Authentication",
        "Basic test",
        "Basic Mode",
    ]
    for harmless in negative_cases:
        assert redact_secrets(harmless) == harmless

    secret_header = "Authorization: Basic dXNlcjpzdXBlcnNlY3JldA=="
    evidence = Evidence(
        observed=secret_header,
        expected="Sanitized configuration without credentials",
        details={"header": "authorization: basic YWRtaW46cGFzc3dvcmQxMjM="},
    )
    finding = Finding(
        id="finding-basic-1",
        rule_id="ENV004",
        title=f"Leaked {secret_header}",
        description=f"Detected {secret_header} in config.",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category=Category.ENVIRONMENT,
        file=".env.example",
        evidence=evidence,
        recommendation=f"Remove {secret_header} immediately.",
    )
    result = ScanResult(
        repository=RepositoryContext(repository_name="auth-test"),
        findings=[finding],
        summary=ScanSummary(total_findings=1),
        warnings=[f"Warning for {secret_header}"],
    )

    outputs = [
        TerminalRenderer().render_scan_result_text(result),
        serialize_scan_result(result),
        serialize_markdown_report(result),
        serialize_sarif_report(result),
    ]
    for rendered in outputs:
        assert "dXNlcjpzdXBlcnNlY3JldA" not in rendered
        assert "YWRtaW46cGFzc3dvcmQxMjM" not in rendered
        assert REDACTED_PLACEHOLDER in rendered


def test_unicode_repository_paths_and_report_escaping(tmp_path: Path) -> None:
    repo = tmp_path / "café-app"
    repo.mkdir()
    unicode_pkg = repo / "src" / "модуль"
    unicode_pkg.mkdir(parents=True)
    (unicode_pkg / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "cafe"\nversion = "0.1.0"\n'
        '[project.scripts]\ncli = "bad|mod_[bold red]pwn[/bold red]:main"\n',
        encoding="utf-8",
    )

    result = ScanOrchestrator().scan(repo)
    assert "src/модуль/app.py" in result.repository.discovered_files
    md = serialize_markdown_report(result)
    assert "\\|" in md
    assert "[bold red]pwn[/bold red]" in md
    text = TerminalRenderer().render_scan_result_text(result)
    assert "café-app" in text
    assert "[bold red]pwn[/bold red]" in text


def test_rich_markup_injection_in_paths_findings_evidence_and_remediation(tmp_path: Path) -> None:
    from io import StringIO

    from rich.console import Console

    malicious_strings = [
        "[bold red]pwn[/bold red]",
        "[[red][bold]nested[/bold][/red]]",
        "[bold red",
        "[/]",
        "\\[escaped]",
    ]
    joined = " ".join(malicious_strings)

    # Scan a real repository whose directory and manifest filenames contain Rich markup tokens
    real_repo = tmp_path / "markup-[bold red]repo"
    real_sub = real_repo / "pkg-[yellow]bad"
    real_sub.mkdir(parents=True)
    (real_repo / "pyproject.toml").write_text(
        '[project]\nname = "markup-test"\nversion = "0.1.0"\n'
        '[project.scripts]\ncli = "pkg.[bold red]missing:main"\n',
        encoding="utf-8",
    )
    real_scan = ScanOrchestrator().scan(real_repo)
    real_plain = TerminalRenderer().render_scan_result_text(real_scan)
    assert "markup-[bold red]repo" in real_plain
    assert "[bold red]missing:main" in real_plain

    rel_file = "pkg/[yellow]bad[/yellow]/config.toml"

    finding = Finding(
        id="finding-markup-1",
        rule_id="PY002",
        title=f"Title {joined}",
        description=f"Desc {joined}",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category=Category.PYTHON,
        file=rel_file,
        line=3,
        evidence=Evidence(
            observed=f"Observed {joined}",
            expected=f"Expected {joined}",
        ),
        recommendation=f"Fix {joined}",
    )
    result = ScanResult(
        repository=RepositoryContext(repository_name="markup-[red]repo[/red]"),
        findings=[finding],
        summary=ScanSummary(total_findings=1),
        warnings=[f"Warn {joined}"],
    )

    # Render with ANSI enabled to confirm Rich does not inject red styling from untrusted tags
    ansi_buf = StringIO()
    ansi_console = Console(file=ansi_buf, force_terminal=True, color_system="standard", width=160)
    TerminalRenderer().print_scan_result(result, console=ansi_console)
    ansi_out = ansi_buf.getvalue()

    plain_out = TerminalRenderer().render_scan_result_text(result)
    json_out = serialize_scan_result(result)
    md_out = serialize_markdown_report(result)
    sarif_out = serialize_sarif_report(result)

    for payload in malicious_strings:
        assert payload in plain_out
        assert payload in ansi_out
        assert payload in json_out
        assert payload in md_out
        assert payload in sarif_out

    assert "markup-[red]repo[/red]" in plain_out
    assert rel_file in plain_out
    # ANSI red SGR code (\x1b[31m) must not be triggered by untrusted [bold red] tag
    assert "\x1b[1;31mpwn" not in ansi_out
    assert "\x1b[31mpwn" not in ansi_out


def test_non_secret_key_names_not_falsely_redacted() -> None:
    from diagora.core.security import is_sensitive_key

    benign_keys = {
        "primary_key": "user_id",
        "foreign_key": "account_id",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPublicKeyValue",
        "sort_key": "created_at",
        "cache_key": "users:v1:list",
    }
    for key_name, val in benign_keys.items():
        assert is_sensitive_key(key_name) is False
        assert redact_secrets(f"{key_name}={val}") == f"{key_name}={val}"
        assert redact_secrets(f"{key_name.upper()}: {val}") == f"{key_name.upper()}: {val}"

    redacted_map = redact_value(benign_keys)
    assert redacted_map == benign_keys

    evidence = Evidence(observed=benign_keys, expected="Schema metadata")
    assert evidence.observed == benign_keys

    # Confirm real secret key names remain strictly redacted
    secret_keys = {
        "api_key": "live_api_val_12345",
        "private_key": "live_priv_val_12345",
        "access_key": "live_access_val_12345",
        "secret_key": "live_secret_val_12345",
        "signing_key": "live_sign_val_12345",
        "encryption_key": "live_enc_val_12345",
        "master_key": "live_master_val_12345",
        "google_key": "live_google_val_12345",
        "stripe_key": "live_stripe_val_12345",
    }
    for key_name, val in secret_keys.items():
        assert is_sensitive_key(key_name) is True
        assert REDACTED_PLACEHOLDER in redact_secrets(f"{key_name.upper()}={val}")
        assert val not in redact_secrets(f"{key_name.upper()}={val}")

    redacted_secrets_map = redact_value(secret_keys)
    assert all(v == REDACTED_PLACEHOLDER for v in redacted_secrets_map.values())
