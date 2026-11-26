"""Static environment variable and secret hygiene analyzer implementing ENV001-ENV006."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.configuration import (
    EnvEntry,
    parse_env_file,
    parse_json_safe,
    parse_toml_safe,
    parse_yaml_safe,
)
from diagora.core.classifier import DOCKER_COMPOSE_NAMES
from diagora.core.exceptions import DiagoraError
from diagora.core.models import (
    Category,
    Confidence,
    Ecosystem,
    Finding,
    RepositoryContext,
)
from diagora.core.security import detect_secret_pattern, is_sensitive_key, safe_read_text
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings

_EXAMPLE_ENV_NAMES = frozenset({".env.example", ".env.sample"})

_SYSTEM_ENV_VARS = frozenset(
    {
        "CI",
        "HOME",
        "HOSTNAME",
        "LANG",
        "LC_ALL",
        "OLDPWD",
        "PATH",
        "PWD",
        "SHELL",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "USERNAME",
    }
)

_PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "change_me",
        "dummy",
        "example",
        "placeholder",
        "replace-me",
        "replace_me",
        "secret",
        "test",
        "todo",
        "your-api-key",
        "your_api_key",
        "your-secret",
        "your_secret",
        "your-token",
        "your_token",
        "xxx",
    }
)

_INTERP_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:([:?]?[-?]?)(.*?))?\}")
_CODE_ENV_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""os\.environ(?:\.get)?\s*[\[\(]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""os\.getenv\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)"""),
    re.compile(r"""process\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""),
)
_SOURCE_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")


@dataclass(frozen=True, slots=True)
class _VarReference:
    name: str
    file: str
    line: int | None
    required_no_default: bool = False


def _is_env_filename(rel_path: str) -> bool:
    name = PurePosixPath(rel_path).name
    return name == ".env" or (name.startswith(".env.") and not name.endswith((".bak", ".orig")))


def _is_example_env_file(rel_path: str) -> bool:
    return PurePosixPath(rel_path).name in _EXAMPLE_ENV_NAMES


def _is_system_var(name: str) -> bool:
    return (
        name in _SYSTEM_ENV_VARS
        or name.startswith("GITHUB_")
        or name.startswith("RUNNER_")
        or name.startswith("ACTIONS_")
    )


def _is_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return True
    lower = cleaned.lower()
    if lower in _PLACEHOLDER_VALUES:
        return True
    if lower.startswith(("your_", "your-", "<", "example_", "dummy_", "${")):
        return True
    return set(cleaned) <= {"*", "x", "X", "."}


def _find_text_line(text: str, needle: str) -> int | None:
    if not needle:
        return None
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return idx
    return None


def _extract_interpolations(
    value: Any,
    rel_path: str,
    text: str,
    out: list[_VarReference],
) -> None:
    if isinstance(value, str):
        for match in _INTERP_RE.finditer(value):
            var_name = match.group(1)
            op = match.group(2) or ""
            required = op.startswith((":?", "?"))
            if not _is_system_var(var_name):
                out.append(
                    _VarReference(
                        name=var_name,
                        file=rel_path,
                        line=_find_text_line(text, match.group(0)),
                        required_no_default=required,
                    )
                )
    elif isinstance(value, list):
        for item in value:
            _extract_interpolations(item, rel_path, text, out)
    elif isinstance(value, dict):
        for item in value.values():
            _extract_interpolations(item, rel_path, text, out)


def _extract_compose_env_refs(
    data: dict[str, Any],
    rel_path: str,
    text: str,
    refs: list[_VarReference],
    requires_example_trigger: list[str],
) -> None:
    _extract_interpolations(data, rel_path, text, refs)
    services = data.get("services")
    if not isinstance(services, dict):
        return
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        if svc.get("env_file"):
            requires_example_trigger.append(rel_path)
        env_block = svc.get("environment")
        if isinstance(env_block, dict):
            for k, v in env_block.items():
                key = str(k).strip()
                if key and not _is_system_var(key):
                    is_passthru = v is None or v == "" or (isinstance(v, str) and "${" in v)
                    refs.append(
                        _VarReference(
                            name=key,
                            file=rel_path,
                            line=_find_text_line(text, key),
                        )
                    )
                    if is_passthru:
                        requires_example_trigger.append(rel_path)
        elif isinstance(env_block, list):
            for item in env_block:
                if not isinstance(item, str):
                    continue
                if "=" in item:
                    key, rhs = item.split("=", 1)
                    key = key.strip()
                    if key and not _is_system_var(key):
                        refs.append(
                            _VarReference(
                                name=key,
                                file=rel_path,
                                line=_find_text_line(text, key),
                            )
                        )
                        if not rhs.strip() or "${" in rhs:
                            requires_example_trigger.append(rel_path)
                else:
                    key = item.strip()
                    if key and not _is_system_var(key):
                        refs.append(
                            _VarReference(
                                name=key,
                                file=rel_path,
                                line=_find_text_line(text, key),
                            )
                        )
                        requires_example_trigger.append(rel_path)


def _extract_deploy_env_refs(
    rel_path: str,
    text: str,
    refs: list[_VarReference],
    requires_example_trigger: list[str],
) -> None:
    name = PurePosixPath(rel_path).name
    data: Any = None
    if name in {"vercel.json", "railway.json"}:
        data, err, _ = parse_json_safe(text)
        if err or not isinstance(data, dict):
            return
        env_map = data.get("env")
        if isinstance(env_map, dict):
            for k, v in env_map.items():
                key = str(k).strip()
                if key and not _is_system_var(key):
                    refs.append(
                        _VarReference(name=key, file=rel_path, line=_find_text_line(text, key))
                    )
                    if isinstance(v, str) and (v.startswith("@") or "${" in v):
                        requires_example_trigger.append(rel_path)
    elif name == "render.yaml":
        data, err, _ = parse_yaml_safe(text)
        if err or not isinstance(data, dict):
            return
        services = data.get("services")
        if isinstance(services, list):
            for svc in services:
                if not isinstance(svc, dict):
                    continue
                env_vars = svc.get("envVars")
                if isinstance(env_vars, list):
                    for item in env_vars:
                        if isinstance(item, dict) and item.get("key"):
                            key = str(item["key"]).strip()
                            if not _is_system_var(key):
                                refs.append(
                                    _VarReference(
                                        name=key,
                                        file=rel_path,
                                        line=_find_text_line(text, key),
                                    )
                                )
                                if item.get("sync") is False or "value" not in item:
                                    requires_example_trigger.append(rel_path)
    elif name in {"fly.toml", "netlify.toml"}:
        data, err, _ = parse_toml_safe(text)
        if err or not isinstance(data, dict):
            return
        env_table = (
            data.get("env")
            if name == "fly.toml"
            else (
                data.get("build", {}).get("environment")
                if isinstance(data.get("build"), dict)
                else None
            )
        )
        if isinstance(env_table, dict):
            for k in env_table:
                key = str(k).strip()
                if key and not _is_system_var(key):
                    refs.append(
                        _VarReference(name=key, file=rel_path, line=_find_text_line(text, key))
                    )


class EnvironmentAnalyzer(BaseAnalyzer):
    """Deterministic static analyzer for environment templates and secrets (ENV001-ENV006)."""

    name = "environment"
    category = Category.ENVIRONMENT
    supported_ecosystems = ()

    def supports(self, context: RepositoryContext) -> bool:
        """Run on non-empty supported or env-configured repositories."""
        if context.is_empty:
            return False
        has_env = any(_is_env_filename(f) for f in context.discovered_files)
        return bool(
            has_env
            or context.docker_files
            or context.ci_workflows
            or context.deployment_manifests
            or (
                {Ecosystem.PYTHON, Ecosystem.NODE, Ecosystem.DOCKER}
                & set(context.detected_ecosystems)
            )
        )

    def analyze(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> list[Finding]:
        """Inspect `.env*` files, Compose/deployment references, and tracked files for secrets."""
        findings: list[Finding] = []
        counter = 0

        def next_id() -> str:
            nonlocal counter
            counter += 1
            return f"env-{counter:04d}"

        all_env_files = sorted(
            {
                *(f for f in context.discovered_files if _is_env_filename(f)),
                *(f for f in context.configuration_files if _is_env_filename(f)),
            }
        )
        example_files = [f for f in all_env_files if _is_example_env_file(f)]
        non_example_env_files = [f for f in all_env_files if not _is_example_env_file(f)]

        parsed_examples: dict[str, list[EnvEntry]] = {}
        parsed_non_examples: dict[str, list[EnvEntry]] = {}
        example_keys: set[str] = set()
        non_example_keys: set[str] = set()

        for rel_path in all_env_files:
            try:
                text = safe_read_text(
                    rel_path,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue

            entries = parse_env_file(text)
            if _is_example_env_file(rel_path):
                parsed_examples[rel_path] = entries
                example_keys.update(e.key for e in entries)
            else:
                parsed_non_examples[rel_path] = entries
                non_example_keys.update(e.key for e in entries)

            # ENV005: duplicate or conflicting keys within the same env file
            seen_entries: dict[str, EnvEntry] = {}
            for entry in entries:
                prev = seen_entries.get(entry.key)
                if prev is not None:
                    conflict = prev.value != entry.value
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ENV005",
                            observed=(
                                f"Key '{entry.key}' redeclared on line {entry.line} "
                                f"({'conflicting values' if conflict else 'duplicate declaration'})"
                            ),
                            expected=f"Single canonical declaration of '{entry.key}'",
                            details={
                                "key": entry.key,
                                "first_line": prev.line,
                                "duplicate_line": entry.line,
                                "conflicting_values": conflict,
                            },
                            file=rel_path,
                            line=entry.line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    seen_entries[entry.key] = entry

            # ENV003 & ENV004 on env entries
            is_example = _is_example_env_file(rel_path)
            for entry in entries:
                self._check_env_entry_value(
                    entry=entry,
                    rel_path=rel_path,
                    is_example=is_example,
                    findings=findings,
                    next_id=next_id,
                    rule_registry=rule_registry,
                )

        # Extract env var references from Compose & deployment manifests
        refs: list[_VarReference] = []
        requires_example_trigger: list[str] = []

        for rel_path in sorted(context.docker_files):
            if PurePosixPath(rel_path).name not in DOCKER_COMPOSE_NAMES:
                continue
            try:
                text = safe_read_text(
                    rel_path,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            self._scan_text_for_secrets(rel_path, text, findings, next_id, rule_registry)
            data, err, _ = parse_yaml_safe(text)
            if not err and isinstance(data, dict):
                _extract_compose_env_refs(data, rel_path, text, refs, requires_example_trigger)

        for rel_path in sorted(context.deployment_manifests):
            try:
                text = safe_read_text(
                    rel_path,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            self._scan_text_for_secrets(rel_path, text, findings, next_id, rule_registry)
            _extract_deploy_env_refs(rel_path, text, refs, requires_example_trigger)

        # Scan CI workflows and other config files for committed secrets (ENV004)
        scanned_secret_files = (
            set(all_env_files) | set(context.docker_files) | set(context.deployment_manifests)
        )
        for rel_path in sorted(set(context.ci_workflows) | set(context.configuration_files)):
            if rel_path in scanned_secret_files or PurePosixPath(rel_path).name == ".gitignore":
                continue
            try:
                text = safe_read_text(
                    rel_path,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            self._scan_text_for_secrets(rel_path, text, findings, next_id, rule_registry)

        # Deduplicate references by variable name preserving first location
        first_ref_by_name: dict[str, _VarReference] = {}
        for ref in refs:
            if ref.name not in first_ref_by_name:
                first_ref_by_name[ref.name] = ref

        # Also gather references from non-example .env files for ENV002
        for rel_path, entries in parsed_non_examples.items():
            for entry in entries:
                if not _is_system_var(entry.key) and entry.key not in first_ref_by_name:
                    first_ref_by_name[entry.key] = _VarReference(
                        name=entry.key,
                        file=rel_path,
                        line=entry.line,
                    )

        # Check required ${VAR:?msg} interpolations in Compose without an example/env value (ENV003)
        known_populated = {
            e.key
            for entries in (*parsed_examples.values(), *parsed_non_examples.values())
            for e in entries
            if e.has_value
        }
        for ref in refs:
            if ref.required_no_default and ref.name not in known_populated:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ENV003",
                        observed=f"Required variable '${{{ref.name}:?...}}' has no declared value",
                        expected=f"Declare a value or fallback for '{ref.name}'",
                        details={"key": ref.name},
                        file=ref.file,
                        line=ref.line,
                        confidence=Confidence.HIGH,
                    )
                )

        # ENV001: Missing .env.example / .env.sample when env config is actively used
        if not example_files and (non_example_env_files or requires_example_trigger):
            evidence_file = (
                non_example_env_files[0] if non_example_env_files else requires_example_trigger[0]
            )
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ENV001",
                    observed=(
                        "Environment variables or `.env` used without `.env.example`/`.env.sample`"
                    ),
                    expected="Repository provides `.env.example` or `.env.sample`",
                    details={
                        "trigger_files": sorted(
                            set(non_example_env_files + requires_example_trigger)
                        )
                    },
                    file=evidence_file,
                    confidence=Confidence.HIGH,
                )
            )
            return findings

        # ENV002: Referenced variable missing from .env.example / .env.sample
        if example_files:
            for var_name in sorted(first_ref_by_name):
                if var_name not in example_keys:
                    ref = first_ref_by_name[var_name]
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ENV002",
                            observed=(
                                f"Variable '{var_name}' referenced in '{ref.file}' "
                                f"is absent from {example_files[0]}"
                            ),
                            expected=f"'{var_name}' documented in {example_files[0]}",
                            details={"variable": var_name, "example_files": example_files},
                            file=ref.file,
                            line=ref.line,
                            confidence=Confidence.HIGH,
                        )
                    )

            # ENV006: Unused variable in .env.example (check code references too to avoid FPs)
            code_vars = self._collect_code_env_vars(repo_root, context, settings)
            used_vars = set(first_ref_by_name.keys()) | non_example_keys | code_vars
            for ex_file, entries in parsed_examples.items():
                for entry in entries:
                    if entry.key not in used_vars:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ENV006",
                                observed=(
                                    f"Example variable '{entry.key}' is not referenced "
                                    "in config or source files"
                                ),
                                expected=(
                                    f"Reference '{entry.key}' in configuration/code "
                                    "or remove stale entry"
                                ),
                                details={"variable": entry.key},
                                file=ex_file,
                                line=entry.line,
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings

    def _check_env_entry_value(
        self,
        *,
        entry: EnvEntry,
        rel_path: str,
        is_example: bool,
        findings: list[Finding],
        next_id: Any,
        rule_registry: RuleRegistry,
    ) -> None:
        comment_lower = entry.comment.lower()
        is_optional = "optional" in comment_lower or "nullable" in comment_lower
        is_marked_required = "required" in comment_lower

        # ENV003: empty declaration
        if (
            not entry.has_value
            and not is_optional
            and (not is_example or not is_sensitive_key(entry.key) or is_marked_required)
        ):
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ENV003",
                    observed=(
                        f"Environment variable '{entry.key}' is declared with an empty value"
                    ),
                    expected=f"Non-empty value or placeholder for '{entry.key}'",
                    details={"key": entry.key, "file": rel_path},
                    file=rel_path,
                    line=entry.line,
                    confidence=Confidence.HIGH if not is_example else Confidence.MEDIUM,
                )
            )

        # ENV004: secret pattern or live credential in tracked env file
        if entry.has_value and not _is_placeholder(entry.value):
            secret_label = detect_secret_pattern(entry.value)
            if secret_label is not None:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ENV004",
                        observed=f"Detected {secret_label} assigned to '{entry.key}'",
                        expected="Use placeholder values instead of committed credentials",
                        details={"key": entry.key, "pattern": secret_label},
                        file=rel_path,
                        line=entry.line,
                        confidence=Confidence.CONFIRMED,
                    )
                )
            elif not is_example and is_sensitive_key(entry.key):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ENV004",
                        observed=(
                            f"Tracked environment file defines sensitive key '{entry.key}' "
                            "with a literal value"
                        ),
                        expected="Do not commit non-example `.env` files containing credentials",
                        details={"key": entry.key},
                        file=rel_path,
                        line=entry.line,
                        confidence=Confidence.HIGH,
                    )
                )

    def _scan_text_for_secrets(
        self,
        rel_path: str,
        text: str,
        findings: list[Finding],
        next_id: Any,
        rule_registry: RuleRegistry,
    ) -> None:
        if (detect_secret_pattern(text) or "") == "PEM private key":
            line_no = _find_text_line(text, "PRIVATE KEY-----") or 1
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ENV004",
                    observed=f"Detected PEM private key inside '{rel_path}'",
                    expected="Store private keys outside tracked repository files",
                    details={"pattern": "PEM private key"},
                    file=rel_path,
                    line=line_no,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return

        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            label = detect_secret_pattern(stripped)
            if label is None:
                continue
            if "example" in stripped.lower() or "placeholder" in stripped.lower():
                continue
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ENV004",
                    observed=f"Detected {label} in '{rel_path}'",
                    expected="Replace committed credentials with environment variable placeholders",
                    details={"pattern": label},
                    file=rel_path,
                    line=line_no,
                    confidence=Confidence.CONFIRMED,
                )
            )

    def _collect_code_env_vars(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
    ) -> set[str]:
        found: set[str] = set()
        code_files = [f for f in context.discovered_files if f.endswith(_SOURCE_EXTENSIONS)][:200]
        for rel_path in code_files:
            try:
                text = safe_read_text(
                    rel_path,
                    repo_root,
                    max_bytes=min(settings.max_file_size_bytes, 512 * 1024),
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            for pattern in _CODE_ENV_PATTERNS:
                for match in pattern.finditer(text):
                    found.add(match.group(1))
        return found
