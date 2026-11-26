"""Static CI/CD and deployment manifest analyzer implementing rules DP001-DP003."""

from __future__ import annotations

import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.configuration import (
    find_yaml_key_line,
    parse_json_safe,
    parse_toml_safe,
    parse_yaml_safe,
)
from diagora.core.exceptions import DiagoraError, PathSecurityError
from diagora.core.models import (
    Category,
    Confidence,
    Ecosystem,
    Finding,
    RepositoryContext,
)
from diagora.core.security import safe_read_text, validate_within_root
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings

_SCRIPT_EXTS = (".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1")
_INTERPRETERS = frozenset({"bash", "sh", "zsh", "python", "python3", "node", "tsx"})
_SPEC_CLAUSE_RE = re.compile(r"^\s*(>=|<=|==|!=|~=|>|<|\^)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_VERCEL_PY_RUNTIME_RE = re.compile(r"^python(\d+)\.(\d+)$", re.IGNORECASE)
_MAJOR_MINOR_RE = re.compile(r"v?(\d+)(?:\.(\d+))?")
_CREATION_HINTS = ("mkdir ", "touch ", "cat >", "cat >>", "tee ", "> ")


def _parse_ver_tuple(raw: str) -> tuple[int, int] | None:
    match = _MAJOR_MINOR_RE.search(raw.strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    return major, minor


def _version_satisfies_constraint(version_raw: str, spec_raw: str) -> bool | None:
    """Evaluate simple major/minor constraint specs (`>=3.10,<4`, `>=20`, `^20.0.0`, `20.x`)."""
    ver = _parse_ver_tuple(version_raw)
    if ver is None:
        return None

    spec = spec_raw.strip()
    if not spec or spec in {"*", "latest", "lts/*", "node"}:
        return None

    # Support OR-ed Node ranges (`18 || 20` or `>=18 || >=20`)
    if "||" in spec:
        outcomes = [_version_satisfies_constraint(version_raw, part) for part in spec.split("||")]
        decided = [o for o in outcomes if o is not None]
        return any(decided) if decided else None

    clauses = [c.strip() for c in re.split(r"[, ]+", spec) if c.strip()]
    checked_any = False
    for clause in clauses:
        if clause.endswith(".x"):
            clause = clause[:-2]
        match = _SPEC_CLAUSE_RE.match(clause)
        if not match:
            continue
        checked_any = True
        op = match.group(1) or "=="
        req_major = int(match.group(2))
        req_minor = int(match.group(3)) if match.group(3) is not None else None
        req_tuple = (req_major, req_minor if req_minor is not None else 0)

        if op == ">=":
            if ver < req_tuple:
                return False
        elif op == ">":
            if ver <= req_tuple:
                return False
        elif op == "<=":
            if req_minor is None and ver[0] > req_major:
                return False
            if req_minor is not None and ver > req_tuple:
                return False
        elif op == "<":
            if ver >= req_tuple:
                return False
        elif op == "!=":
            if req_minor is None and ver[0] == req_major:
                return False
            if req_minor is not None and ver == req_tuple:
                return False
        elif op in {"~=", "^"}:
            if ver[0] != req_major or (req_minor is not None and ver < req_tuple):
                return False
        else:  # == or bare version pin like "3.11" or "20"
            if req_minor is None:
                if ver[0] != req_major:
                    return False
            elif ver != req_tuple:
                return False

    return True if checked_any else None


def _extract_local_script_targets(command_text: str) -> list[str]:
    """Extract explicit local repository script paths from shell command lines."""
    targets: list[str] = []
    created_hints: set[str] = set()

    for raw_line in command_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if any(hint in line for hint in _CREATION_HINTS):
            for tok in line.split():
                if tok.startswith("./") or tok.endswith(_SCRIPT_EXTS):
                    created_hints.add(tok.lstrip("./"))
        if "${{" in line or "$" in line:
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            tokens = line.split()
        if not tokens:
            continue

        candidate: str | None = None
        first = tokens[0]
        if first.startswith("./") or (
            "/" in first and first.endswith(_SCRIPT_EXTS) and not first.startswith("/")
        ):
            candidate = first
        elif first in _INTERPRETERS:
            for arg in tokens[1:]:
                if arg.startswith("-"):
                    continue
                if arg.startswith("./") or arg.endswith(_SCRIPT_EXTS):
                    candidate = arg
                break

        if candidate and candidate.lstrip("./") not in created_hints:
            targets.append(candidate)

    return targets


def _find_line_for_needle(text: str, needle: str, start_line: int = 1) -> int:
    lines = text.splitlines()
    for idx in range(max(1, start_line), len(lines) + 1):
        if needle in lines[idx - 1]:
            return idx
    return start_line


class DeploymentAnalyzer(BaseAnalyzer):
    """Deterministic static analyzer for CI/CD and deployment manifests (DP001-DP003)."""

    name = "deployment"
    category = Category.DEPLOYMENT
    supported_ecosystems = (
        Ecosystem.GITHUB_ACTIONS,
        Ecosystem.VERCEL,
        Ecosystem.GENERIC_DEPLOYMENT,
    )

    def analyze(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> list[Finding]:
        """Inspect GitHub Actions workflows and deployment manifests."""
        findings: list[Finding] = []
        counter = 0

        def next_id() -> str:
            nonlocal counter
            counter += 1
            return f"dp-{counter:04d}"

        py_spec, py_source = self._read_project_python_constraint(repo_root, context, settings)
        node_spec, node_source = self._read_project_node_constraint(repo_root, context, settings)

        for wf_path in sorted(context.ci_workflows):
            self._analyze_workflow(
                wf_path=wf_path,
                repo_root=repo_root,
                settings=settings,
                py_spec=py_spec,
                py_source=py_source,
                node_spec=node_spec,
                node_source=node_source,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

        for dep_path in sorted(context.deployment_manifests):
            self._analyze_deployment_manifest(
                dep_path=dep_path,
                repo_root=repo_root,
                settings=settings,
                py_spec=py_spec,
                py_source=py_source,
                node_spec=node_spec,
                node_source=node_source,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

        return findings

    def _read_project_python_constraint(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
    ) -> tuple[str | None, str | None]:
        for manifest in sorted(context.manifests):
            if PurePosixPath(manifest).name != "pyproject.toml":
                continue
            try:
                text = safe_read_text(
                    manifest,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            data, err, _ = parse_toml_safe(text)
            if not err and isinstance(data, dict):
                project = data.get("project")
                if isinstance(project, dict) and isinstance(project.get("requires-python"), str):
                    return project["requires-python"].strip(), manifest
                poetry = (
                    data.get("tool", {}).get("poetry", {}).get("dependencies")
                    if isinstance(data.get("tool"), dict)
                    else None
                )
                if isinstance(poetry, dict) and isinstance(poetry.get("python"), str):
                    return poetry["python"].strip(), manifest

        for cfg in sorted(context.configuration_files):
            name = PurePosixPath(cfg).name
            if name not in {".python-version", "runtime.txt"}:
                continue
            try:
                text = safe_read_text(
                    cfg,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                ).strip()
            except DiagoraError:
                continue
            if name == ".python-version" and text:
                ver = text.splitlines()[0].strip()
                if _parse_ver_tuple(ver) is not None:
                    return ver, cfg
            if name == "runtime.txt" and text.lower().startswith("python-"):
                ver = text.split("-", 1)[1].strip()
                if _parse_ver_tuple(ver) is not None:
                    return ver, cfg

        return None, None

    def _read_project_node_constraint(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
    ) -> tuple[str | None, str | None]:
        for manifest in sorted(context.manifests):
            if PurePosixPath(manifest).name != "package.json":
                continue
            try:
                text = safe_read_text(
                    manifest,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            data, err, _ = parse_json_safe(text)
            if not err and isinstance(data, dict):
                engines = data.get("engines")
                if isinstance(engines, dict) and isinstance(engines.get("node"), str):
                    return engines["node"].strip(), manifest

        for cfg in sorted(context.configuration_files):
            name = PurePosixPath(cfg).name
            if name not in {".nvmrc", ".node-version"}:
                continue
            try:
                text = safe_read_text(
                    cfg,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                ).strip()
            except DiagoraError:
                continue
            if text:
                ver = text.splitlines()[0].strip()
                if _parse_ver_tuple(ver) is not None:
                    return ver, cfg

        return None, None

    def _check_path_exists(
        self,
        *,
        target: str,
        base_dir: str,
        manifest_path: str,
        line: int,
        repo_root: Path,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
        kind_label: str,
    ) -> None:
        cleaned = target.strip().replace("\\", "/")
        if not cleaned or "${" in cleaned or "$" in cleaned or "*" in cleaned:
            return
        rel = cleaned if base_dir in {"", "."} else f"{base_dir.rstrip('/')}/{cleaned}"
        try:
            resolved = validate_within_root(
                rel,
                repo_root,
                follow_symlinks=settings.follow_symlinks,
            )
            exists = resolved.exists()
        except PathSecurityError:
            exists = False

        if not exists:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DP002",
                    observed=(
                        f"{kind_label} '{cleaned}' referenced in '{manifest_path}' does not exist"
                    ),
                    expected=f"Existing {kind_label.lower()} at '{cleaned}' inside repository",
                    details={"referenced_path": cleaned, "manifest": manifest_path},
                    file=manifest_path,
                    line=line,
                    confidence=Confidence.HIGH,
                )
            )

    def _analyze_workflow(
        self,
        *,
        wf_path: str,
        repo_root: Path,
        settings: ScanSettings,
        py_spec: str | None,
        py_source: str | None,
        node_spec: str | None,
        node_source: str | None,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        try:
            text = safe_read_text(
                wf_path,
                repo_root,
                max_bytes=settings.max_file_size_bytes,
                follow_symlinks=settings.follow_symlinks,
            )
        except DiagoraError:
            return

        data, err, err_line = parse_yaml_safe(text)
        if err is not None or not isinstance(data, dict):
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DP001",
                    observed=err or "Workflow file root must be a YAML mapping",
                    expected="Valid GitHub Actions workflow YAML mapping",
                    details={"error": err or "invalid_root"},
                    file=wf_path,
                    line=err_line or 1,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return

        # PyYAML parses bare `on:` as boolean True
        has_on = "on" in data or True in data
        jobs = data.get("jobs")
        if not has_on or not isinstance(jobs, dict) or not jobs:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DP001",
                    observed=(
                        "GitHub Actions workflow is missing required `on` trigger or `jobs` mapping"
                    ),
                    expected="Top-level `on` trigger and non-empty `jobs` mapping",
                    details={"has_on": has_on, "has_jobs": isinstance(jobs, dict) and bool(jobs)},
                    file=wf_path,
                    line=find_yaml_key_line(text, "jobs") or 1,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return

        for job_name, job_cfg in jobs.items():
            if not isinstance(job_cfg, dict):
                continue
            job_line = find_yaml_key_line(text, str(job_name)) or 1
            job_wd = str(
                job_cfg.get("defaults", {}).get("run", {}).get("working-directory", ".")
                if isinstance(job_cfg.get("defaults"), dict)
                and isinstance(job_cfg.get("defaults", {}).get("run"), dict)
                else "."
            )
            matrix = (
                job_cfg.get("strategy", {}).get("matrix")
                if isinstance(job_cfg.get("strategy"), dict)
                else None
            )
            steps = job_cfg.get("steps")
            if not isinstance(steps, list):
                continue

            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str) and uses.strip().startswith("./"):
                    self._check_path_exists(
                        target=uses.strip(),
                        base_dir=".",
                        manifest_path=wf_path,
                        line=_find_line_for_needle(text, uses.strip(), job_line),
                        repo_root=repo_root,
                        settings=settings,
                        rule_registry=rule_registry,
                        findings=findings,
                        next_id=next_id,
                        kind_label="Local workflow action",
                    )

                run_cmd = step.get("run")
                if isinstance(run_cmd, str):
                    wd = str(step.get("working-directory") or job_wd or ".")
                    for script_path in _extract_local_script_targets(run_cmd):
                        self._check_path_exists(
                            target=script_path,
                            base_dir=wd,
                            manifest_path=wf_path,
                            line=_find_line_for_needle(text, script_path, job_line),
                            repo_root=repo_root,
                            settings=settings,
                            rule_registry=rule_registry,
                            findings=findings,
                            next_id=next_id,
                            kind_label="Deployment script",
                        )

                # DP003: runtime checks for setup-python & setup-node
                if isinstance(uses, str) and isinstance(step.get("with"), dict):
                    with_cfg = step["with"]
                    if "actions/setup-python" in uses and py_spec and py_source:
                        self._check_ci_runtime(
                            raw_val=with_cfg.get("python-version"),
                            matrix=matrix,
                            matrix_key="python-version",
                            project_spec=py_spec,
                            project_source=py_source,
                            runtime_name="Python",
                            wf_path=wf_path,
                            text=text,
                            start_line=job_line,
                            rule_registry=rule_registry,
                            findings=findings,
                            next_id=next_id,
                        )
                    if "actions/setup-node" in uses and node_spec and node_source:
                        self._check_ci_runtime(
                            raw_val=with_cfg.get("node-version"),
                            matrix=matrix,
                            matrix_key="node-version",
                            project_spec=node_spec,
                            project_source=node_source,
                            runtime_name="Node.js",
                            wf_path=wf_path,
                            text=text,
                            start_line=job_line,
                            rule_registry=rule_registry,
                            findings=findings,
                            next_id=next_id,
                        )

    def _check_ci_runtime(
        self,
        *,
        raw_val: Any,
        matrix: Any,
        matrix_key: str,
        project_spec: str,
        project_source: str,
        runtime_name: str,
        wf_path: str,
        text: str,
        start_line: int,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        if raw_val is None:
            return
        val_str = str(raw_val).strip()

        # Avoid false positives on multi-version matrices unless NO matrix version satisfies spec
        if "${{" in val_str:
            if isinstance(matrix, dict) and isinstance(matrix.get(matrix_key), list):
                candidates = [str(v) for v in matrix[matrix_key]]
                checks = [_version_satisfies_constraint(c, project_spec) for c in candidates]
                decided = [c for c in checks if c is not None]
                if decided and not any(decided):
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="DP003",
                            observed=(
                                f"CI {runtime_name} matrix {candidates} satisfies none of "
                                f"project constraint '{project_spec}' ({project_source})"
                            ),
                            expected=f"Matrix versions compatible with '{project_spec}'",
                            details={
                                "runtime": runtime_name,
                                "ci_versions": candidates,
                                "project_constraint": project_spec,
                                "project_source": project_source,
                            },
                            file=wf_path,
                            line=find_yaml_key_line(text, matrix_key, start_line) or start_line,
                            confidence=Confidence.HIGH,
                        )
                    )
            return

        ok = _version_satisfies_constraint(val_str, project_spec)
        if ok is False:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DP003",
                    observed=(
                        f"CI workflow specifies {runtime_name} '{val_str}', conflicting with "
                        f"'{project_spec}' declared in {project_source}"
                    ),
                    expected=f"{runtime_name} version matching '{project_spec}'",
                    details={
                        "runtime": runtime_name,
                        "ci_version": val_str,
                        "project_constraint": project_spec,
                        "project_source": project_source,
                    },
                    file=wf_path,
                    line=find_yaml_key_line(text, matrix_key, start_line) or start_line,
                    confidence=Confidence.HIGH,
                )
            )

    def _analyze_deployment_manifest(
        self,
        *,
        dep_path: str,
        repo_root: Path,
        settings: ScanSettings,
        py_spec: str | None,
        py_source: str | None,
        node_spec: str | None,
        node_source: str | None,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        try:
            text = safe_read_text(
                dep_path,
                repo_root,
                max_bytes=settings.max_file_size_bytes,
                follow_symlinks=settings.follow_symlinks,
            )
        except DiagoraError:
            return

        name = PurePosixPath(dep_path).name
        base_dir = PurePosixPath(dep_path).parent.as_posix()

        if name in {"vercel.json", "railway.json"}:
            data, err, err_line = parse_json_safe(text)
            if err is not None or not isinstance(data, dict):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DP001",
                        observed=err or f"Invalid JSON in {name}",
                        expected=f"Valid JSON object in {name}",
                        details={"error": err or "invalid_json"},
                        file=dep_path,
                        line=err_line or 1,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                return

            if name == "vercel.json":
                self._check_vercel_manifest(
                    data=data,
                    dep_path=dep_path,
                    base_dir=base_dir,
                    text=text,
                    repo_root=repo_root,
                    settings=settings,
                    py_spec=py_spec,
                    py_source=py_source,
                    node_spec=node_spec,
                    node_source=node_source,
                    rule_registry=rule_registry,
                    findings=findings,
                    next_id=next_id,
                )

        elif name == "render.yaml":
            data, err, err_line = parse_yaml_safe(text)
            if err is not None or not isinstance(data, dict):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DP001",
                        observed=err or "Invalid YAML in render.yaml",
                        expected="Valid YAML mapping in render.yaml",
                        details={"error": err or "invalid_yaml"},
                        file=dep_path,
                        line=err_line or 1,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                return
            services = data.get("services")
            if isinstance(services, list):
                for svc in services:
                    if not isinstance(svc, dict):
                        continue
                    df_path = svc.get("dockerfilePath")
                    if isinstance(df_path, str):
                        self._check_path_exists(
                            target=df_path,
                            base_dir=base_dir,
                            manifest_path=dep_path,
                            line=_find_line_for_needle(text, df_path),
                            repo_root=repo_root,
                            settings=settings,
                            rule_registry=rule_registry,
                            findings=findings,
                            next_id=next_id,
                            kind_label="Dockerfile",
                        )
                    for cmd_key in ("buildCommand", "startCommand"):
                        cmd = svc.get(cmd_key)
                        if isinstance(cmd, str):
                            for target in _extract_local_script_targets(cmd):
                                self._check_path_exists(
                                    target=target,
                                    base_dir=base_dir,
                                    manifest_path=dep_path,
                                    line=_find_line_for_needle(text, target),
                                    repo_root=repo_root,
                                    settings=settings,
                                    rule_registry=rule_registry,
                                    findings=findings,
                                    next_id=next_id,
                                    kind_label="Deployment script",
                                )

        elif name in {"fly.toml", "netlify.toml"}:
            data, err, err_line = parse_toml_safe(text)
            if err is not None or not isinstance(data, dict):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DP001",
                        observed=err or f"Invalid TOML in {name}",
                        expected=f"Valid TOML in {name}",
                        details={"error": err or "invalid_toml"},
                        file=dep_path,
                        line=err_line or 1,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                return
            build = data.get("build")
            if isinstance(build, dict):
                if name == "fly.toml" and isinstance(build.get("dockerfile"), str):
                    self._check_path_exists(
                        target=build["dockerfile"],
                        base_dir=base_dir,
                        manifest_path=dep_path,
                        line=_find_line_for_needle(text, build["dockerfile"]),
                        repo_root=repo_root,
                        settings=settings,
                        rule_registry=rule_registry,
                        findings=findings,
                        next_id=next_id,
                        kind_label="Dockerfile",
                    )
                if name == "netlify.toml":
                    if isinstance(build.get("command"), str):
                        for target in _extract_local_script_targets(build["command"]):
                            self._check_path_exists(
                                target=target,
                                base_dir=base_dir,
                                manifest_path=dep_path,
                                line=_find_line_for_needle(text, target),
                                repo_root=repo_root,
                                settings=settings,
                                rule_registry=rule_registry,
                                findings=findings,
                                next_id=next_id,
                                kind_label="Build script",
                            )
                    env_tbl = build.get("environment")
                    if isinstance(env_tbl, dict):
                        self._check_runtime_env_map(
                            env_tbl=env_tbl,
                            dep_path=dep_path,
                            text=text,
                            py_spec=py_spec,
                            py_source=py_source,
                            node_spec=node_spec,
                            node_source=node_source,
                            rule_registry=rule_registry,
                            findings=findings,
                            next_id=next_id,
                        )

    def _check_vercel_manifest(
        self,
        *,
        data: dict[str, Any],
        dep_path: str,
        base_dir: str,
        text: str,
        repo_root: Path,
        settings: ScanSettings,
        py_spec: str | None,
        py_source: str | None,
        node_spec: str | None,
        node_source: str | None,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        builds = data.get("builds")
        if isinstance(builds, list):
            for entry in builds:
                if isinstance(entry, dict) and isinstance(entry.get("src"), str):
                    src = entry["src"]
                    if "*" not in src:
                        self._check_path_exists(
                            target=src,
                            base_dir=base_dir,
                            manifest_path=dep_path,
                            line=_find_line_for_needle(text, src),
                            repo_root=repo_root,
                            settings=settings,
                            rule_registry=rule_registry,
                            findings=findings,
                            next_id=next_id,
                            kind_label="Vercel build source",
                        )

        build_cmd = data.get("buildCommand")
        if isinstance(build_cmd, str):
            for target in _extract_local_script_targets(build_cmd):
                self._check_path_exists(
                    target=target,
                    base_dir=base_dir,
                    manifest_path=dep_path,
                    line=_find_line_for_needle(text, target),
                    repo_root=repo_root,
                    settings=settings,
                    rule_registry=rule_registry,
                    findings=findings,
                    next_id=next_id,
                    kind_label="Build script",
                )

        engines = data.get("engines")
        if (
            isinstance(engines, dict)
            and isinstance(engines.get("node"), str)
            and node_spec
            and node_source
        ):
            vercel_node = engines["node"].strip()
            ok = _version_satisfies_constraint(vercel_node, node_spec)
            if ok is False:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DP003",
                        observed=(
                            f"vercel.json declares Node.js '{vercel_node}', conflicting with "
                            f"'{node_spec}' in {node_source}"
                        ),
                        expected=f"Node.js version matching '{node_spec}'",
                        details={
                            "runtime": "Node.js",
                            "deployment_version": vercel_node,
                            "project_constraint": node_spec,
                            "project_source": node_source,
                        },
                        file=dep_path,
                        line=_find_line_for_needle(text, '"engines"'),
                        confidence=Confidence.HIGH,
                    )
                )

        functions = data.get("functions")
        if isinstance(functions, dict) and py_spec and py_source:
            for fn_cfg in functions.values():
                if not isinstance(fn_cfg, dict) or not isinstance(fn_cfg.get("runtime"), str):
                    continue
                rt = fn_cfg["runtime"].strip()
                match = _VERCEL_PY_RUNTIME_RE.match(rt)
                if match:
                    py_ver = f"{match.group(1)}.{match.group(2)}"
                    if _version_satisfies_constraint(py_ver, py_spec) is False:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="DP003",
                                observed=(
                                    f"vercel.json function runtime '{rt}' conflicts with "
                                    f"'{py_spec}' in {py_source}"
                                ),
                                expected=f"Python runtime compatible with '{py_spec}'",
                                details={
                                    "runtime": "Python",
                                    "deployment_version": py_ver,
                                    "project_constraint": py_spec,
                                    "project_source": py_source,
                                },
                                file=dep_path,
                                line=_find_line_for_needle(text, rt),
                                confidence=Confidence.HIGH,
                            )
                        )

    def _check_runtime_env_map(
        self,
        *,
        env_tbl: dict[str, Any],
        dep_path: str,
        text: str,
        py_spec: str | None,
        py_source: str | None,
        node_spec: str | None,
        node_source: str | None,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        if "PYTHON_VERSION" in env_tbl and py_spec and py_source:
            ver = str(env_tbl["PYTHON_VERSION"]).strip()
            if _version_satisfies_constraint(ver, py_spec) is False:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DP003",
                        observed=(
                            f"PYTHON_VERSION='{ver}' in {dep_path} conflicts with "
                            f"'{py_spec}' ({py_source})"
                        ),
                        expected=f"Python version matching '{py_spec}'",
                        details={"deployment_version": ver, "project_constraint": py_spec},
                        file=dep_path,
                        line=_find_line_for_needle(text, "PYTHON_VERSION"),
                        confidence=Confidence.HIGH,
                    )
                )
        if "NODE_VERSION" in env_tbl and node_spec and node_source:
            ver = str(env_tbl["NODE_VERSION"]).strip()
            if _version_satisfies_constraint(ver, node_spec) is False:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DP003",
                        observed=(
                            f"NODE_VERSION='{ver}' in {dep_path} conflicts with "
                            f"'{node_spec}' ({node_source})"
                        ),
                        expected=f"Node.js version matching '{node_spec}'",
                        details={"deployment_version": ver, "project_constraint": node_spec},
                        file=dep_path,
                        line=_find_line_for_needle(text, "NODE_VERSION"),
                        confidence=Confidence.HIGH,
                    )
                )
