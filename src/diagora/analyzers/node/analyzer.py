"""Static Node.js repository analyzer implementing rules ND001-ND009."""

from __future__ import annotations

import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.node.parsers import (
    engines_allows_major,
    expand_workspace_patterns,
    extract_major_version,
    find_json_key_line,
    is_valid_node_version_file,
    parse_json_safe,
    parse_package_lock,
    parse_package_manager_field,
    parse_pnpm_lock,
    parse_pnpm_workspace,
    parse_tsconfig_safe,
    parse_yarn_lock,
)
from diagora.core.exceptions import DiagoraError
from diagora.core.models import (
    Category,
    Confidence,
    Ecosystem,
    Finding,
    RepositoryContext,
    Severity,
    SubprojectInfo,
)
from diagora.core.security import safe_read_text, validate_within_root
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings

_SCRIPT_RUNNERS = frozenset({"node", "tsx", "ts-node", "babel-node", "bun", "sh", "bash"})
_LOCAL_EXTS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh")
_SHELL_SPLITTER_RE = re.compile(r"(?:&&|\|\||;)")


def _join_rel(subproject_path: str, filename: str) -> str:
    cleaned = filename.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if subproject_path in {"", "."}:
        return cleaned
    return f"{subproject_path.strip('/')}/{cleaned}"


def _is_local_script_target(token: str) -> bool:
    if not token or token.startswith(("-", "$", "%", "http://", "https://")):
        return False
    if token.startswith(("./", "../")):
        return True
    return bool("/" in token and token.endswith(_LOCAL_EXTS))


class NodeAnalyzer(BaseAnalyzer):
    """Deterministic static analyzer for Node.js projects and workspaces (ND001-ND009)."""

    name = "node"
    category = Category.NODE
    supported_ecosystems = (Ecosystem.NODE,)

    def analyze(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> list[Finding]:
        """Inspect Node.js projects, workspaces, lockfiles, and TypeScript configs."""
        findings: list[Finding] = []
        counter = 0

        def next_id() -> str:
            nonlocal counter
            counter += 1
            return f"nd-{counter:04d}"

        node_subprojects = [sp for sp in context.subprojects if Ecosystem.NODE in sp.ecosystems]
        all_node_dirs = [sp.path for sp in node_subprojects]

        # Pre-read package.json files across all Node subprojects so workspace validation
        # knows declared workspace package names and workspace membership.
        parsed_packages: dict[str, tuple[dict[str, Any] | None, str | None]] = {}
        for sp in node_subprojects:
            pkg_rel = next(
                (m for m in sp.manifests if PurePosixPath(m).name == "package.json"),
                None,
            )
            if pkg_rel is not None:
                text, _ = self._safe_read(pkg_rel, repo_root, settings)
                if text is not None:
                    data, err, _ = parse_json_safe(text)
                    parsed_packages[sp.path] = (data if err is None else None, text)
                else:
                    parsed_packages[sp.path] = (None, None)

        # Map workspace child directories -> workspace root directory
        workspace_parent: dict[str, str] = {}
        workspace_children: dict[str, list[str]] = {}
        workspace_member_names: dict[str, set[str]] = {}

        for sp in node_subprojects:
            pkg_data, _ = parsed_packages.get(sp.path, (None, None))
            patterns = self._extract_workspace_patterns(
                sp=sp,
                pkg_data=pkg_data,
                repo_root=repo_root,
                settings=settings,
                context=context,
            )
            if patterns is not None:
                matched_dirs, _ = expand_workspace_patterns(patterns, all_node_dirs, sp.path)
                workspace_children[sp.path] = matched_dirs
                member_names: set[str] = set()
                for child_dir in matched_dirs:
                    workspace_parent[child_dir] = sp.path
                    child_pkg, _ = parsed_packages.get(child_dir, (None, None))
                    if isinstance(child_pkg, dict) and isinstance(child_pkg.get("name"), str):
                        member_names.add(child_pkg["name"])
                workspace_member_names[sp.path] = member_names

        for sp in node_subprojects:
            ws_root = workspace_parent.get(sp.path)
            ws_root_pkg = parsed_packages.get(ws_root, (None, None))[0] if ws_root else None
            ws_root_sp = next((item for item in node_subprojects if item.path == ws_root), None)
            findings.extend(
                self._analyze_subproject(
                    sp=sp,
                    all_node_dirs=all_node_dirs,
                    parsed_packages=parsed_packages,
                    ws_root=ws_root,
                    ws_root_sp=ws_root_sp,
                    ws_root_pkg=ws_root_pkg,
                    ws_member_names=(
                        workspace_member_names.get(sp.path)
                        or (workspace_member_names.get(ws_root) if ws_root else None)
                        or set()
                    ),
                    repo_root=repo_root,
                    context=context,
                    settings=settings,
                    rule_registry=rule_registry,
                    next_id=next_id,
                )
            )

        # Also validate standalone tsconfig.json files if no package.json exists at root
        if not node_subprojects:
            for cfg_rel in context.configuration_files:
                if PurePosixPath(cfg_rel).name == "tsconfig.json":
                    self._check_tsconfig(
                        tsconfig_rel=cfg_rel,
                        sp_path=".",
                        repo_root=repo_root,
                        settings=settings,
                        rule_registry=rule_registry,
                        next_id=next_id,
                        findings=findings,
                    )

        return findings

    def _safe_read(
        self,
        rel_path: str,
        repo_root: Path,
        settings: ScanSettings,
    ) -> tuple[str | None, str | None]:
        try:
            text = safe_read_text(
                rel_path,
                repo_root,
                max_bytes=settings.max_file_size_bytes,
                follow_symlinks=settings.follow_symlinks,
            )
            return text, None
        except DiagoraError as exc:
            return None, exc.message

    def _extract_workspace_patterns(
        self,
        *,
        sp: SubprojectInfo,
        pkg_data: dict[str, Any] | None,
        repo_root: Path,
        settings: ScanSettings,
        context: RepositoryContext,
    ) -> list[str] | None:
        pnpm_ws_rel = _join_rel(sp.path, "pnpm-workspace.yaml")
        if pnpm_ws_rel in context.discovered_files:
            ws_text, _ = self._safe_read(pnpm_ws_rel, repo_root, settings)
            if ws_text is not None:
                patterns, err, _ = parse_pnpm_workspace(ws_text)
                if err is None and patterns is not None:
                    return patterns
        if isinstance(pkg_data, dict):
            ws_val = pkg_data.get("workspaces")
            if isinstance(ws_val, list) and all(isinstance(x, str) for x in ws_val):
                return list(ws_val)
            if isinstance(ws_val, dict) and isinstance(ws_val.get("packages"), list):
                return [str(x) for x in ws_val["packages"] if isinstance(x, str)]
        return None

    def _analyze_subproject(
        self,
        *,
        sp: SubprojectInfo,
        all_node_dirs: list[str],
        parsed_packages: dict[str, tuple[dict[str, Any] | None, str | None]],
        ws_root: str | None,
        ws_root_sp: SubprojectInfo | None,
        ws_root_pkg: dict[str, Any] | None,
        ws_member_names: set[str],
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []
        sp_path = sp.path
        sp_prefix = "" if sp_path in {"", "."} else f"{sp_path.strip('/')}/"
        sp_file_set = {
            f for f in context.discovered_files if not sp_prefix or f.startswith(sp_prefix)
        }

        pkg_rel = next((m for m in sp.manifests if PurePosixPath(m).name == "package.json"), None)
        pkg_data: dict[str, Any] | None = None
        pkg_text: str | None = None
        pkg_valid = False

        if pkg_rel is not None:
            pkg_text, read_err = self._safe_read(pkg_rel, repo_root, settings)
            if pkg_text is None:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND001",
                        observed=read_err or "Unreadable package.json",
                        expected="Readable UTF-8 package.json",
                        file=pkg_rel,
                        confidence=Confidence.CONFIRMED,
                    )
                )
            else:
                parsed, json_err, json_line = parse_json_safe(pkg_text)
                if json_err is not None or parsed is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND001",
                            observed=json_err or "Invalid JSON",
                            expected="Valid JSON object in package.json",
                            file=pkg_rel,
                            line=json_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    pkg_data = parsed
                    pkg_valid = self._validate_package_json_schema(
                        pkg_data=pkg_data,
                        pkg_text=pkg_text,
                        pkg_rel=pkg_rel,
                        rule_registry=rule_registry,
                        next_id=next_id,
                        findings=findings,
                    )

        # Inspect tsconfig.json in this subproject (ND008)
        tsconfig_rel = _join_rel(sp_path, "tsconfig.json")
        tsconfig_outdir: str | None = None
        if tsconfig_rel in sp_file_set:
            tsconfig_outdir = self._check_tsconfig(
                tsconfig_rel=tsconfig_rel,
                sp_path=sp_path,
                repo_root=repo_root,
                settings=settings,
                rule_registry=rule_registry,
                next_id=next_id,
                findings=findings,
            )

        # Inspect lockfiles in THIS subproject directory (ND003)
        local_lockfiles = sorted(PurePosixPath(lf).name for lf in sp.lockfiles)
        local_lockfile_paths = {PurePosixPath(lf).name: lf for lf in sp.lockfiles}
        if len(local_lockfiles) > 1:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ND003",
                    observed=f"Multiple lockfiles in '{sp_path}': {', '.join(local_lockfiles)}",
                    expected="A single lockfile matching the project's package manager",
                    details={"directory": sp_path, "lockfiles": local_lockfiles},
                    file=local_lockfile_paths[local_lockfiles[0]],
                    confidence=Confidence.CONFIRMED,
                )
            )

        if not pkg_valid or pkg_data is None or pkg_text is None or pkg_rel is None:
            return findings

        # ND002: packageManager declaration (skip workspace children if root declares it)
        pkg_manager_raw = pkg_data.get("packageManager")
        declared_pm_name: str | None = None
        if pkg_manager_raw is not None:
            if not isinstance(pkg_manager_raw, str):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND001",
                        title="Invalid packageManager field in package.json",
                        description=(
                            "`packageManager` must be a string formatted as `<pm>@<version>`."
                        ),
                        observed=repr(pkg_manager_raw),
                        expected="String such as `pnpm@9.0.0`",
                        file=pkg_rel,
                        line=find_json_key_line(pkg_text, "packageManager"),
                        confidence=Confidence.CONFIRMED,
                    )
                )
            else:
                parsed_pm = parse_package_manager_field(pkg_manager_raw)
                if parsed_pm is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND002",
                            title="Malformed packageManager declaration",
                            description=(
                                "`packageManager` should follow Corepack `<name>@<semver>` syntax."
                            ),
                            observed=pkg_manager_raw,
                            expected="Corepack string like `npm@10.0.0` or `pnpm@9.0.0`",
                            file=pkg_rel,
                            line=find_json_key_line(pkg_text, "packageManager"),
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    declared_pm_name = parsed_pm[0]
                    # Check mismatch between packageManager and local lockfile (ND003)
                    expected_lock = {
                        "npm": "package-lock.json",
                        "pnpm": "pnpm-lock.yaml",
                        "yarn": "yarn.lock",
                    }.get(declared_pm_name)
                    if (
                        expected_lock
                        and len(local_lockfiles) == 1
                        and local_lockfiles[0] != expected_lock
                    ):
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND003",
                                title="packageManager conflicts with committed lockfile",
                                description=(
                                    f"`packageManager` specifies `{declared_pm_name}`, "
                                    f"but `{local_lockfiles[0]}` is committed."
                                ),
                                observed=(
                                    f"packageManager={pkg_manager_raw}, "
                                    f"lockfile={local_lockfiles[0]}"
                                ),
                                expected=(
                                    f"Lockfile `{expected_lock}` matching `{declared_pm_name}`"
                                ),
                                file=pkg_rel,
                                line=find_json_key_line(pkg_text, "packageManager"),
                                confidence=Confidence.CONFIRMED,
                            )
                        )
        elif ws_root is None or not (
            isinstance(ws_root_pkg, dict) and ws_root_pkg.get("packageManager")
        ):
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ND002",
                    observed="No `packageManager` field in package.json",
                    expected="Corepack `packageManager` field (e.g., `pnpm@9.0.0`)",
                    file=pkg_rel,
                    confidence=Confidence.CONFIRMED,
                )
            )

        # ND004: Node.js engine requirement & version consistency
        self._check_node_engine(
            sp_path=sp_path,
            sp_file_set=sp_file_set,
            pkg_data=pkg_data,
            pkg_text=pkg_text,
            pkg_rel=pkg_rel,
            ws_root=ws_root,
            ws_root_pkg=ws_root_pkg,
            repo_root=repo_root,
            context=context,
            settings=settings,
            rule_registry=rule_registry,
            next_id=next_id,
            findings=findings,
        )

        # ND005: Invalid script configuration
        self._check_scripts(
            sp_path=sp_path,
            sp_file_set=sp_file_set,
            pkg_data=pkg_data,
            pkg_text=pkg_text,
            pkg_rel=pkg_rel,
            repo_root=repo_root,
            settings=settings,
            rule_registry=rule_registry,
            next_id=next_id,
            findings=findings,
        )

        # ND006: Missing referenced entry points
        self._check_entry_points(
            sp_path=sp_path,
            sp_file_set=sp_file_set,
            pkg_data=pkg_data,
            pkg_text=pkg_text,
            pkg_rel=pkg_rel,
            tsconfig_outdir=tsconfig_outdir,
            rule_registry=rule_registry,
            next_id=next_id,
            findings=findings,
        )

        # ND007: Workspace configuration & workspace:* dependency consistency
        self._check_workspaces(
            sp=sp,
            all_node_dirs=all_node_dirs,
            pkg_data=pkg_data,
            pkg_text=pkg_text,
            pkg_rel=pkg_rel,
            ws_member_names=ws_member_names,
            repo_root=repo_root,
            context=context,
            settings=settings,
            rule_registry=rule_registry,
            next_id=next_id,
            findings=findings,
        )

        # ND009: Lockfile vs package.json dependency consistency
        self._check_lockfile_consistency(
            sp=sp,
            pkg_data=pkg_data,
            pkg_rel=pkg_rel,
            ws_root=ws_root,
            ws_root_sp=ws_root_sp,
            repo_root=repo_root,
            settings=settings,
            rule_registry=rule_registry,
            next_id=next_id,
            findings=findings,
        )

        return findings

    def _validate_package_json_schema(
        self,
        *,
        pkg_data: dict[str, Any],
        pkg_text: str,
        pkg_rel: str,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> bool:
        valid = True
        name = pkg_data.get("name")
        if name is not None and (not isinstance(name, str) or not name.strip()):
            valid = False
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ND001",
                    title="Invalid `name` in package.json",
                    description="The `name` field in package.json must be a non-empty string.",
                    observed=repr(name),
                    expected="Non-empty string",
                    file=pkg_rel,
                    line=find_json_key_line(pkg_text, "name"),
                    confidence=Confidence.CONFIRMED,
                )
            )
        for obj_field in (
            "scripts",
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
            "engines",
        ):
            val = pkg_data.get(obj_field)
            if val is not None and not isinstance(val, dict):
                valid = False
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND001",
                        title=f"Invalid `{obj_field}` field in package.json",
                        description=f"`{obj_field}` must be a JSON object.",
                        observed=type(val).__name__,
                        expected="JSON object",
                        file=pkg_rel,
                        line=find_json_key_line(pkg_text, obj_field),
                        confidence=Confidence.CONFIRMED,
                    )
                )
            elif isinstance(val, dict) and obj_field != "scripts":
                for dep_name, dep_ver in val.items():
                    if not isinstance(dep_ver, str) or not dep_ver.strip():
                        valid = False
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND001",
                                title=f"Invalid version specifier in `{obj_field}`",
                                description=(
                                    f"Dependency `{dep_name}` must map to a non-empty "
                                    "version string."
                                ),
                                observed=f"{dep_name}: {dep_ver!r}",
                                expected="Non-empty semver/range string",
                                file=pkg_rel,
                                line=find_json_key_line(pkg_text, str(dep_name)),
                                confidence=Confidence.CONFIRMED,
                            )
                        )
        return valid

    def _check_node_engine(
        self,
        *,
        sp_path: str,
        sp_file_set: set[str],
        pkg_data: dict[str, Any],
        pkg_text: str,
        pkg_rel: str,
        ws_root: str | None,
        ws_root_pkg: dict[str, Any] | None,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        engines = pkg_data.get("engines")
        engines_node = (
            engines.get("node")
            if isinstance(engines, dict) and isinstance(engines.get("node"), str)
            else None
        )

        # Check .npmrc for engine-strict=true
        npmrc_engine_strict = False
        npmrc_rel = _join_rel(sp_path, ".npmrc")
        if npmrc_rel in sp_file_set:
            npmrc_text, _ = self._safe_read(npmrc_rel, repo_root, settings)
            if npmrc_text is not None:
                for raw_ln in npmrc_text.splitlines():
                    cleaned_ln = raw_ln.strip()
                    if not cleaned_ln or cleaned_ln.startswith(("#", ";")):
                        continue
                    if "=" in cleaned_ln:
                        k, v = cleaned_ln.split("=", 1)
                        if k.strip() == "engine-strict" and v.strip().lower() == "true":
                            npmrc_engine_strict = True

        # Check .nvmrc and .node-version
        version_file_val: str | None = None
        version_file_rel: str | None = None
        for v_name in (".nvmrc", ".node-version"):
            v_rel = _join_rel(sp_path, v_name)
            if v_rel in sp_file_set:
                v_text, _ = self._safe_read(v_rel, repo_root, settings)
                if v_text is not None:
                    parsed_v, is_ok = is_valid_node_version_file(v_text)
                    if not is_ok:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND004",
                                title=f"Invalid Node.js version in {v_name}",
                                description=(
                                    f"{v_name} does not contain a recognized Node.js version."
                                ),
                                observed=parsed_v or "<empty>",
                                expected="Node.js version (e.g., `20`, `v20.11.0`, or `lts/*`)",
                                file=v_rel,
                                line=1,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                            )
                        )
                    else:
                        version_file_val = parsed_v
                        version_file_rel = v_rel

        # Cross-check engines.node vs .nvmrc / .node-version
        if engines_node and version_file_val:
            major = extract_major_version(version_file_val)
            if major is not None and not engines_allows_major(engines_node, major):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND004",
                        title="Node.js runtime version mismatch between manifest and version file",
                        description=(
                            f"`{version_file_rel}` specifies Node `{version_file_val}`, which "
                            f"conflicts with `engines.node` (`{engines_node}`)."
                        ),
                        observed=(
                            f"{version_file_rel}={version_file_val}, engines.node={engines_node}"
                        ),
                        expected=(
                            "Aligned Node.js major version across package.json and version file"
                        ),
                        file=version_file_rel,
                        line=1,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                    )
                )

        if engines_node or version_file_val:
            return

        # Workspace child inherits engine config from workspace root if present
        if ws_root is not None:
            ws_engines = ws_root_pkg.get("engines") if isinstance(ws_root_pkg, dict) else None
            ws_has_engine = isinstance(ws_engines, dict) and isinstance(ws_engines.get("node"), str)
            ws_has_vfile = any(
                _join_rel(ws_root, vf) in context.discovered_files
                for vf in (".nvmrc", ".node-version")
            )
            if ws_has_engine or ws_has_vfile:
                return

        findings.append(
            rule_registry.create_finding(
                finding_id=next_id(),
                rule_id="ND004",
                observed="No `engines.node`, `.nvmrc`, or `.node-version` declared",
                expected="Node.js version requirement (e.g., `engines.node: '>=20'`)",
                details={"engine_strict": npmrc_engine_strict},
                file=pkg_rel,
                line=find_json_key_line(pkg_text, "name"),
                severity=Severity.HIGH if npmrc_engine_strict else None,
                confidence=Confidence.CONFIRMED,
            )
        )

    def _check_scripts(
        self,
        *,
        sp_path: str,
        sp_file_set: set[str],
        pkg_data: dict[str, Any],
        pkg_text: str,
        pkg_rel: str,
        repo_root: Path,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        scripts = pkg_data.get("scripts")
        if not isinstance(scripts, dict):
            return

        for script_name, script_cmd in scripts.items():
            line_no = find_json_key_line(pkg_text, str(script_name))
            if not isinstance(script_cmd, str) or not script_cmd.strip():
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND005",
                        observed=f"{script_name}: {script_cmd!r}",
                        expected="Non-empty command string",
                        file=pkg_rel,
                        line=line_no,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                continue

            for sub_cmd in _SHELL_SPLITTER_RE.split(script_cmd):
                sub_clean = sub_cmd.strip()
                if not sub_clean:
                    continue
                try:
                    tokens = shlex.split(sub_clean)
                except ValueError:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND005",
                            observed=f"{script_name}: {script_cmd}",
                            expected="Syntactically balanced script command",
                            file=pkg_rel,
                            line=line_no,
                            confidence=Confidence.HIGH,
                        )
                    )
                    break

                if not tokens:
                    continue

                # Skip leading ENV=VAL assignments
                idx = 0
                while idx < len(tokens) and "=" in tokens[idx] and not tokens[idx].startswith("-"):
                    idx += 1
                if idx >= len(tokens):
                    continue

                cmd_bin = tokens[idx]
                target_token: str | None = None
                if _is_local_script_target(cmd_bin):
                    target_token = cmd_bin
                elif cmd_bin in _SCRIPT_RUNNERS:
                    for arg in tokens[idx + 1 :]:
                        if arg.startswith("-"):
                            continue
                        if _is_local_script_target(arg):
                            target_token = arg
                        break

                if target_token is not None:
                    rel_target = _join_rel(sp_path, target_token)
                    try:
                        resolved = validate_within_root(
                            rel_target,
                            repo_root,
                            follow_symlinks=settings.follow_symlinks,
                        )
                        if not resolved.exists():
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="ND005",
                                    observed=(
                                        f"Script '{script_name}' references missing "
                                        f"file '{target_token}'"
                                    ),
                                    expected=f"Existing script target at '{rel_target}'",
                                    file=pkg_rel,
                                    line=line_no,
                                    confidence=Confidence.HIGH,
                                )
                            )
                    except DiagoraError:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND005",
                                observed=(
                                    f"Script '{script_name}' escapes repository "
                                    f"via '{target_token}'"
                                ),
                                expected="Script path strictly within repository root",
                                file=pkg_rel,
                                line=line_no,
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                            )
                        )

    def _check_entry_points(
        self,
        *,
        sp_path: str,
        sp_file_set: set[str],
        pkg_data: dict[str, Any],
        pkg_text: str,
        pkg_rel: str,
        tsconfig_outdir: str | None,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        targets: list[tuple[str, str]] = []
        for field in ("main", "module", "types", "typings"):
            val = pkg_data.get(field)
            if isinstance(val, str) and val.strip():
                targets.append((field, val.strip()))

        bin_val = pkg_data.get("bin")
        if isinstance(bin_val, str) and bin_val.strip():
            targets.append(("bin", bin_val.strip()))
        elif isinstance(bin_val, dict):
            for bin_k, bin_target in bin_val.items():
                if isinstance(bin_target, str) and bin_target.strip():
                    targets.append((f"bin.{bin_k}", bin_target.strip()))

        for field_name, target_rel_raw in targets:
            norm_target = target_rel_raw.replace("\\", "/").lstrip("./")
            full_rel = _join_rel(sp_path, norm_target)
            candidates = (
                full_rel,
                f"{full_rel}.js",
                f"{full_rel}.mjs",
                f"{full_rel}.cjs",
                f"{full_rel}/index.js",
            )
            if any(c in sp_file_set for c in candidates):
                continue

            is_compiled_outdir = bool(
                tsconfig_outdir
                and norm_target.startswith(f"{tsconfig_outdir.strip('./').rstrip('/')}/")
            )
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ND006",
                    observed=f"`{field_name}` points to missing file '{target_rel_raw}'",
                    expected=f"Existing entry point file at '{full_rel}'",
                    details={
                        "field": field_name,
                        "in_tsconfig_outdir": is_compiled_outdir,
                    },
                    file=pkg_rel,
                    line=find_json_key_line(pkg_text, field_name.split(".")[0]),
                    severity=Severity.LOW if is_compiled_outdir else Severity.HIGH,
                    confidence=Confidence.MEDIUM if is_compiled_outdir else Confidence.HIGH,
                )
            )

    def _check_workspaces(
        self,
        *,
        sp: SubprojectInfo,
        all_node_dirs: list[str],
        pkg_data: dict[str, Any],
        pkg_text: str,
        pkg_rel: str,
        ws_member_names: set[str],
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        # 1. Validate pnpm-workspace.yaml
        pnpm_ws_rel = _join_rel(sp.path, "pnpm-workspace.yaml")
        if pnpm_ws_rel in context.discovered_files:
            ws_text, _ = self._safe_read(pnpm_ws_rel, repo_root, settings)
            if ws_text is not None:
                patterns, ws_err, ws_line = parse_pnpm_workspace(ws_text)
                if ws_err is not None or patterns is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND007",
                            observed=ws_err or "Invalid pnpm-workspace.yaml",
                            expected="Valid YAML with `packages:` glob list",
                            file=pnpm_ws_rel,
                            line=ws_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    _, unmatched = expand_workspace_patterns(patterns, all_node_dirs, sp.path)
                    if unmatched:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND007",
                                observed=f"Unmatched workspace globs: {', '.join(unmatched)}",
                                expected="Workspace globs matching directories with package.json",
                                file=pnpm_ws_rel,
                                confidence=Confidence.CONFIRMED,
                            )
                        )

        # 2. Validate package.json `workspaces`
        ws_field = pkg_data.get("workspaces")
        if ws_field is not None:
            patterns_list: list[str] | None = None
            if isinstance(ws_field, list) and all(isinstance(x, str) for x in ws_field):
                patterns_list = list(ws_field)
            elif isinstance(ws_field, dict) and isinstance(ws_field.get("packages"), list):
                patterns_list = [str(x) for x in ws_field["packages"] if isinstance(x, str)]
            else:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND007",
                        observed=f"Invalid `workspaces` type: {type(ws_field).__name__}",
                        expected="Array of workspace glob strings",
                        file=pkg_rel,
                        line=find_json_key_line(pkg_text, "workspaces"),
                        confidence=Confidence.CONFIRMED,
                    )
                )
            if patterns_list is not None:
                _, unmatched = expand_workspace_patterns(patterns_list, all_node_dirs, sp.path)
                if unmatched:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND007",
                            observed=f"Unmatched workspace patterns: {', '.join(unmatched)}",
                            expected="Workspace patterns matching actual subpackage directories",
                            file=pkg_rel,
                            line=find_json_key_line(pkg_text, "workspaces"),
                            confidence=Confidence.CONFIRMED,
                        )
                    )

        # 3. Validate `workspace:*` internal package references
        if ws_member_names:
            for dep_sec in ("dependencies", "devDependencies", "peerDependencies"):
                dep_map = pkg_data.get(dep_sec)
                if not isinstance(dep_map, dict):
                    continue
                for dep_name, dep_ver in dep_map.items():
                    if (
                        isinstance(dep_ver, str)
                        and dep_ver.startswith("workspace:")
                        and dep_name not in ws_member_names
                    ):
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND007",
                                observed=f"'{dep_name}: {dep_ver}' not found in workspace",
                                expected=f"Workspace package named '{dep_name}'",
                                file=pkg_rel,
                                line=find_json_key_line(pkg_text, str(dep_name)),
                                confidence=Confidence.CONFIRMED,
                            )
                        )

    def _check_tsconfig(
        self,
        *,
        tsconfig_rel: str,
        sp_path: str,
        repo_root: Path,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> str | None:
        text, read_err = self._safe_read(tsconfig_rel, repo_root, settings)
        if text is None:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ND008",
                    observed=read_err or "Unreadable tsconfig.json",
                    expected="Readable UTF-8 tsconfig.json",
                    file=tsconfig_rel,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        data, err, line = parse_tsconfig_safe(text)
        if err is not None or data is None:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="ND008",
                    observed=err or "Invalid JSON/JSONC syntax in tsconfig.json",
                    expected="Valid JSON/JSONC object in tsconfig.json",
                    file=tsconfig_rel,
                    line=line,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        comp_opts = data.get("compilerOptions")
        outdir: str | None = None
        if comp_opts is not None:
            if not isinstance(comp_opts, dict):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND008",
                        observed=f"compilerOptions is {type(comp_opts).__name__}",
                        expected="JSON object for compilerOptions",
                        file=tsconfig_rel,
                        line=find_json_key_line(text, "compilerOptions"),
                        confidence=Confidence.CONFIRMED,
                    )
                )
            elif isinstance(comp_opts.get("outDir"), str):
                outdir = comp_opts["outDir"]

        extends_val = data.get("extends")
        extends_list: list[str] = []
        if isinstance(extends_val, str):
            extends_list = [extends_val]
        elif isinstance(extends_val, list):
            extends_list = [x for x in extends_val if isinstance(x, str)]

        for ext_target in extends_list:
            if ext_target.startswith(("./", "../")):
                target_rel = _join_rel(sp_path, ext_target)
                candidates = (target_rel, f"{target_rel}.json")
                found = False
                for cand in candidates:
                    try:
                        resolved = validate_within_root(
                            cand,
                            repo_root,
                            follow_symlinks=settings.follow_symlinks,
                        )
                        if resolved.is_file():
                            found = True
                            break
                    except DiagoraError:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="ND008",
                                observed=f"tsconfig extends path '{ext_target}' escapes repository",
                                expected="Relative tsconfig base file inside repository",
                                file=tsconfig_rel,
                                line=find_json_key_line(text, "extends"),
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                            )
                        )
                        found = True
                        break
                if not found:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND008",
                            observed=f"tsconfig `extends` target '{ext_target}' does not exist",
                            expected="Existing base tsconfig JSON file",
                            file=tsconfig_rel,
                            line=find_json_key_line(text, "extends"),
                            confidence=Confidence.CONFIRMED,
                        )
                    )

        return outdir

    def _check_lockfile_consistency(
        self,
        *,
        sp: SubprojectInfo,
        pkg_data: dict[str, Any],
        pkg_rel: str,
        ws_root: str | None,
        ws_root_sp: SubprojectInfo | None,
        repo_root: Path,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        # Collect direct dependencies from package.json
        declared_deps: dict[str, str] = {}
        for dep_sec in ("dependencies", "devDependencies", "optionalDependencies"):
            dep_map = pkg_data.get(dep_sec)
            if isinstance(dep_map, dict):
                for k, v in dep_map.items():
                    if isinstance(v, str):
                        declared_deps[str(k)] = v

        # Determine active lockfile (local or inherited from workspace root)
        effective_lockfiles = sp.lockfiles
        is_workspace_child = False
        if not effective_lockfiles and ws_root_sp is not None and ws_root_sp.lockfiles:
            effective_lockfiles = ws_root_sp.lockfiles
            is_workspace_child = True

        if len(effective_lockfiles) != 1:
            return

        lock_rel = effective_lockfiles[0]
        lock_name = PurePosixPath(lock_rel).name
        lock_text, _ = self._safe_read(lock_rel, repo_root, settings)
        if lock_text is None:
            return

        if lock_name == "package-lock.json":
            root_specs, resolved_vers, err, err_line = parse_package_lock(lock_text)
            if err is not None:
                if not is_workspace_child:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND009",
                            title="Invalid package-lock.json",
                            description=f"package-lock.json could not be parsed: {err}",
                            observed=err,
                            expected="Valid JSON package-lock.json",
                            file=lock_rel,
                            line=err_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                return
            if is_workspace_child or not declared_deps:
                return
            assert root_specs is not None and resolved_vers is not None
            missing = [
                dep
                for dep in sorted(declared_deps)
                if dep not in root_specs and dep not in resolved_vers
            ]
            mismatched = [
                f"{dep} (manifest={declared_deps[dep]}, lock={root_specs[dep]})"
                for dep in sorted(declared_deps)
                if dep in root_specs and root_specs[dep] != declared_deps[dep]
            ]
            if missing or mismatched:
                problems = []
                if missing:
                    problems.append(f"missing={', '.join(missing)}")
                if mismatched:
                    problems.append(f"specifier_mismatch={', '.join(mismatched)}")
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND009",
                        observed="; ".join(problems),
                        expected="package-lock.json synchronized with package.json",
                        file=lock_rel,
                        confidence=Confidence.CONFIRMED,
                    )
                )

        elif lock_name == "pnpm-lock.yaml":
            importers, err, err_line = parse_pnpm_lock(lock_text)
            if err is not None or importers is None:
                if not is_workspace_child:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND009",
                            title="Invalid pnpm-lock.yaml",
                            description=f"pnpm-lock.yaml could not be parsed: {err}",
                            observed=err or "Invalid pnpm-lock.yaml",
                            expected="Valid YAML pnpm-lock.yaml",
                            file=lock_rel,
                            line=err_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                return

            if not declared_deps:
                return

            if is_workspace_child and ws_root is not None:
                root_prefix = "" if ws_root in {"", "."} else f"{ws_root.strip('/')}/"
                importer_key = (
                    sp.path[len(root_prefix) :]
                    if root_prefix and sp.path.startswith(root_prefix)
                    else sp.path
                )
            else:
                importer_key = "."

            importer_deps = importers.get(importer_key)
            if importer_deps is None:
                # Only flag missing importer if the lockfile actually tracks importers
                if importers and declared_deps:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND009",
                            observed=(
                                f"Package '{importer_key}' dependencies not recorded "
                                "in pnpm-lock.yaml"
                            ),
                            expected=f"Importer entry '{importer_key}' in pnpm-lock.yaml",
                            file=pkg_rel,
                            confidence=Confidence.HIGH,
                        )
                    )
                return

            missing = [dep for dep in sorted(declared_deps) if dep not in importer_deps]
            mismatched = [
                f"{dep} (manifest={declared_deps[dep]}, lock={importer_deps[dep]})"
                for dep in sorted(declared_deps)
                if dep in importer_deps and importer_deps[dep] != declared_deps[dep]
            ]
            if missing or mismatched:
                problems = []
                if missing:
                    problems.append(f"missing={', '.join(missing)}")
                if mismatched:
                    problems.append(f"specifier_mismatch={', '.join(mismatched)}")
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND009",
                        observed="; ".join(problems),
                        expected="pnpm-lock.yaml synchronized with package.json",
                        file=lock_rel if not is_workspace_child else pkg_rel,
                        confidence=Confidence.CONFIRMED,
                    )
                )

        elif lock_name == "yarn.lock":
            locked_specs, err, err_line = parse_yarn_lock(lock_text)
            if err is not None or locked_specs is None:
                if not is_workspace_child:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="ND009",
                            title="Invalid yarn.lock",
                            description=f"yarn.lock could not be parsed: {err}",
                            observed=err or "Invalid yarn.lock",
                            expected="Valid yarn.lock",
                            file=lock_rel,
                            line=err_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                return

            if not declared_deps:
                return

            missing_or_mismatch: list[str] = []
            for dep, spec in sorted(declared_deps.items()):
                if spec.startswith(("workspace:", "file:", "link:")):
                    continue
                specs_in_lock = locked_specs.get(dep)
                if not specs_in_lock:
                    missing_or_mismatch.append(f"{dep} (missing)")
                elif spec not in specs_in_lock:
                    missing_or_mismatch.append(
                        f"{dep} (manifest={spec}, lock={sorted(specs_in_lock)[0]})"
                    )
            if missing_or_mismatch:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="ND009",
                        observed="; ".join(missing_or_mismatch),
                        expected="yarn.lock synchronized with package.json",
                        file=lock_rel if not is_workspace_child else pkg_rel,
                        confidence=Confidence.CONFIRMED,
                    )
                )
