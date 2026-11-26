"""Static Python repository analyzer implementing rules PY001-PY010."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.python.parsers import (
    ParsedRequirement,
    RequirementParseError,
    find_line_number,
    find_toml_key_line,
    is_valid_pep440_specifier,
    is_valid_poetry_constraint,
    normalize_package_name,
    parse_pep508_requirement,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements_file,
    parse_setup_cfg_safe,
    parse_setup_py_static,
    parse_toml_safe,
    parse_uv_lock,
    specifiers_conflict,
)
from diagora.core.classifier import NON_MONOREPO_SUBPROJECT_PREFIXES
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

_ENTRY_POINT_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*):([A-Za-z_][A-Za-z0-9_.]*)$"
)
_RUNTIME_TXT_RE = re.compile(r"^python-(\d+\.\d+(?:\.\d+)?)\s*$", re.IGNORECASE)
_PYTHON_VERSION_FILE_RE = re.compile(r"^(\d+\.\d+(?:\.\d+)?)$")
_TEST_CONFIG_FILES = frozenset({"pytest.ini", "tox.ini", "noxfile.py", "conftest.py"})


def _join_rel(subproject_path: str, filename: str) -> str:
    if subproject_path in {"", "."}:
        return filename
    return f"{subproject_path.strip('/')}/{filename}"


def _is_under_non_project_dir(rel_path: str) -> bool:
    normalized = rel_path.lstrip("./")
    if any(normalized.startswith(prefix) for prefix in NON_MONOREPO_SUBPROJECT_PREFIXES):
        return True
    parts = PurePosixPath(normalized).parts
    return bool(parts and parts[0] in {"tests", "test", "scripts", "benchmarks"})


class PythonAnalyzer(BaseAnalyzer):
    """Deterministic static analyzer for Python repositories and subprojects (PY001-PY010)."""

    name = "python"
    category = Category.PYTHON
    supported_ecosystems = (Ecosystem.PYTHON,)

    def analyze(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> list[Finding]:
        """Inspect all Python subprojects and source roots in the repository."""
        findings: list[Finding] = []
        counter = 0

        def next_id() -> str:
            nonlocal counter
            counter += 1
            return f"py-{counter:04d}"

        python_subprojects = [sp for sp in context.subprojects if Ecosystem.PYTHON in sp.ecosystems]

        # Handle repositories with .py files but zero Python manifests anywhere (PY003)
        if not python_subprojects:
            py_sources = [
                f
                for f in context.discovered_files
                if f.endswith(".py") and not _is_under_non_project_dir(f)
            ]
            if py_sources:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="PY003",
                        observed=f"{len(py_sources)} Python file(s) without dependency manifest",
                        expected=(
                            "At least one manifest (pyproject.toml, requirements.txt, "
                            "Pipfile, or setup.py)"
                        ),
                        details={"sample_files": py_sources[:5]},
                        file=py_sources[0],
                        confidence=Confidence.CONFIRMED,
                    )
                )
            return findings

        for subproject in python_subprojects:
            findings.extend(
                self._analyze_subproject(
                    repo_root=repo_root,
                    context=context,
                    subproject=subproject,
                    settings=settings,
                    rule_registry=rule_registry,
                    next_id=next_id,
                )
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

    def _analyze_subproject(
        self,
        *,
        repo_root: Path,
        context: RepositoryContext,
        subproject: SubprojectInfo,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        next_id: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []
        sp_path = subproject.path
        sp_prefix = "" if sp_path in {"", "."} else f"{sp_path.strip('/')}/"

        def in_subproject(rel: str) -> bool:
            if not sp_prefix:
                return True
            return rel.startswith(sp_prefix)

        sp_files = [f for f in context.discovered_files if in_subproject(f)]
        manifests_by_name: dict[str, str] = {}
        for m in subproject.manifests:
            manifests_by_name[PurePosixPath(m).name] = m
        lockfiles_by_name: dict[str, str] = {}
        for lf in subproject.lockfiles:
            lockfiles_by_name[PurePosixPath(lf).name] = lf

        # Check standalone runtime version files
        has_python_version_file = False
        for ver_name in (".python-version", "runtime.txt"):
            ver_rel = _join_rel(sp_path, ver_name)
            if ver_rel in sp_files:
                ver_text, read_err = self._safe_read(ver_rel, repo_root, settings)
                if ver_text is not None:
                    first_line = next(
                        (ln.strip() for ln in ver_text.splitlines() if ln.strip()), ""
                    )
                    if ver_name == ".python-version":
                        if _PYTHON_VERSION_FILE_RE.match(first_line):
                            has_python_version_file = True
                        elif first_line:
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY007",
                                    observed=first_line,
                                    expected="Semantic Python version (e.g., 3.12 or 3.12.1)",
                                    file=ver_rel,
                                    line=1,
                                    confidence=Confidence.HIGH,
                                )
                            )
                    elif ver_name == "runtime.txt":
                        if _RUNTIME_TXT_RE.match(first_line):
                            has_python_version_file = True
                        elif first_line:
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY007",
                                    observed=first_line,
                                    expected="python-X.Y.Z (e.g., python-3.12.1)",
                                    file=ver_rel,
                                    line=1,
                                    confidence=Confidence.HIGH,
                                )
                            )
                elif read_err:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            title=f"Unable to read {ver_name}",
                            description=read_err,
                            observed=read_err,
                            expected="Readable UTF-8 version marker file",
                            file=ver_rel,
                            confidence=Confidence.CONFIRMED,
                        )
                    )

        pyproject_data: dict[str, Any] | None = None
        pyproject_text: str | None = None
        pyproject_rel = manifests_by_name.get("pyproject.toml")
        pyproject_valid = False

        declared_python_version: str | None = None
        declared_python_file: str | None = None
        declared_python_line: int | None = None

        is_poetry_project = False
        is_uv_project = False
        is_pipenv_project = "Pipfile" in manifests_by_name
        has_dev_group = "requirements-dev.txt" in manifests_by_name
        has_build_system = False
        is_distributable_package = False
        poetry_package_mode_false = False
        uv_package_false = False

        # Requirements collected across sources for conflict & lockfile checks
        # tuple: (ParsedRequirement, group_key)
        all_reqs: list[tuple[ParsedRequirement, str]] = []
        pyproject_direct_pkgs: set[str] = set()
        pipfile_direct_pkgs: set[str] = set()

        # 1. Inspect pyproject.toml
        if pyproject_rel is not None:
            pyproject_text, read_err = self._safe_read(pyproject_rel, repo_root, settings)
            if pyproject_text is None:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="PY002",
                        observed=read_err or "Unreadable pyproject.toml",
                        expected="Valid UTF-8 TOML file",
                        file=pyproject_rel,
                        confidence=Confidence.CONFIRMED,
                    )
                )
            else:
                pyproject_data, toml_err, toml_line = parse_toml_safe(pyproject_text)
                if toml_err is not None or pyproject_data is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            observed=toml_err or "Invalid TOML syntax",
                            expected="Valid TOML syntax in pyproject.toml",
                            file=pyproject_rel,
                            line=toml_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    pyproject_valid = True

        if pyproject_valid and pyproject_data is not None and pyproject_text is not None:
            assert pyproject_rel is not None
            has_build_system = isinstance(pyproject_data.get("build-system"), dict)
            project_tbl = pyproject_data.get("project")
            tool_tbl = pyproject_data.get("tool")
            dep_groups_tbl = pyproject_data.get("dependency-groups")

            if isinstance(tool_tbl, dict):
                if isinstance(tool_tbl.get("poetry"), dict):
                    is_poetry_project = True
                    poetry_tbl = tool_tbl["poetry"]
                    if poetry_tbl.get("package-mode") is False:
                        poetry_package_mode_false = True
                if isinstance(tool_tbl.get("uv"), dict):
                    is_uv_project = True
                    uv_tbl = tool_tbl["uv"]
                    if uv_tbl.get("package") is False:
                        uv_package_false = True

            # Validate [project] schema (PEP 621)
            if project_tbl is not None:
                if not isinstance(project_tbl, dict):
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            observed=f"[project] is {type(project_tbl).__name__}",
                            expected="TOML table [project]",
                            file=pyproject_rel,
                            line=find_line_number(pyproject_text, "[project]"),
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    proj_name = project_tbl.get("name")
                    if proj_name is not None and (
                        not isinstance(proj_name, str) or not proj_name.strip()
                    ):
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="PY002",
                                observed=repr(proj_name),
                                expected="Non-empty string for project.name",
                                file=pyproject_rel,
                                line=find_toml_key_line(pyproject_text, "name", section="project"),
                                confidence=Confidence.CONFIRMED,
                            )
                        )
                    elif proj_name is None and not is_poetry_project:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="PY002",
                                observed="Missing `name` key under [project]",
                                expected=(
                                    "PEP 621 requires `project.name` when [project] is defined"
                                ),
                                file=pyproject_rel,
                                line=find_line_number(pyproject_text, "[project]"),
                                confidence=Confidence.CONFIRMED,
                            )
                        )

                    req_py = project_tbl.get("requires-python")
                    if req_py is not None:
                        if not isinstance(req_py, str) or not req_py.strip():
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY007",
                                    observed=repr(req_py),
                                    expected="Non-empty PEP 440 version specifier string",
                                    file=pyproject_rel,
                                    line=find_toml_key_line(
                                        pyproject_text,
                                        "requires-python",
                                        section="project",
                                    ),
                                    confidence=Confidence.CONFIRMED,
                                )
                            )
                        else:
                            declared_python_version = req_py
                            declared_python_file = pyproject_rel
                            declared_python_line = find_toml_key_line(
                                pyproject_text, "requires-python", section="project"
                            )

                    # Validate project.dependencies
                    deps_raw = project_tbl.get("dependencies")
                    if deps_raw is not None:
                        if not isinstance(deps_raw, list) or not all(
                            isinstance(d, str) for d in deps_raw
                        ):
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY002",
                                    observed="project.dependencies must be an array of strings",
                                    expected="Array of PEP 508 dependency strings",
                                    file=pyproject_rel,
                                    line=find_toml_key_line(
                                        pyproject_text,
                                        "dependencies",
                                        section="project",
                                    ),
                                    confidence=Confidence.CONFIRMED,
                                )
                            )
                        else:
                            for dep_str in deps_raw:
                                dep_line = find_line_number(pyproject_text, dep_str)
                                parsed = parse_pep508_requirement(
                                    dep_str, line=dep_line, source_file=pyproject_rel
                                )
                                if isinstance(parsed, RequirementParseError):
                                    findings.append(
                                        rule_registry.create_finding(
                                            finding_id=next_id(),
                                            rule_id="PY005",
                                            title=(
                                                "Invalid dependency declaration in pyproject.toml"
                                            ),
                                            description=parsed.message,
                                            observed=parsed.raw,
                                            expected="Valid PEP 508 dependency string",
                                            file=pyproject_rel,
                                            line=parsed.line,
                                            confidence=Confidence.CONFIRMED,
                                        )
                                    )
                                else:
                                    all_reqs.append((parsed, "runtime"))
                                    pyproject_direct_pkgs.add(parsed.normalized_name)

                    # Validate project.optional-dependencies
                    opt_deps = project_tbl.get("optional-dependencies")
                    if opt_deps is not None:
                        if not isinstance(opt_deps, dict):
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY002",
                                    observed="project.optional-dependencies is not a table",
                                    expected="Table mapping extra names to dependency arrays",
                                    file=pyproject_rel,
                                    line=find_line_number(pyproject_text, "optional-dependencies"),
                                    confidence=Confidence.CONFIRMED,
                                )
                            )
                        else:
                            for extra_name, extra_list in opt_deps.items():
                                if str(extra_name).lower() in {"dev", "test", "tests", "lint"}:
                                    has_dev_group = True
                                if not isinstance(extra_list, list) or not all(
                                    isinstance(x, str) for x in extra_list
                                ):
                                    findings.append(
                                        rule_registry.create_finding(
                                            finding_id=next_id(),
                                            rule_id="PY002",
                                            observed=(
                                                "Invalid array in "
                                                f"optional-dependencies.{extra_name}"
                                            ),
                                            expected="Array of PEP 508 dependency strings",
                                            file=pyproject_rel,
                                            line=find_line_number(pyproject_text, str(extra_name)),
                                            confidence=Confidence.CONFIRMED,
                                        )
                                    )
                                    continue
                                for dep_str in extra_list:
                                    dep_line = find_line_number(pyproject_text, dep_str)
                                    parsed = parse_pep508_requirement(
                                        dep_str, line=dep_line, source_file=pyproject_rel
                                    )
                                    if isinstance(parsed, RequirementParseError):
                                        findings.append(
                                            rule_registry.create_finding(
                                                finding_id=next_id(),
                                                rule_id="PY005",
                                                title=(
                                                    f"Invalid optional dependency in [{extra_name}]"
                                                ),
                                                description=parsed.message,
                                                observed=parsed.raw,
                                                expected="Valid PEP 508 dependency string",
                                                file=pyproject_rel,
                                                line=parsed.line,
                                                confidence=Confidence.CONFIRMED,
                                            )
                                        )
                                    else:
                                        all_reqs.append((parsed, f"extra:{extra_name}"))

                    # Check entry points (PY010)
                    for script_table_key in ("scripts", "gui-scripts"):
                        scripts_tbl = project_tbl.get(script_table_key)
                        if isinstance(scripts_tbl, dict):
                            is_distributable_package = True
                            self._check_entry_points(
                                scripts_tbl=scripts_tbl,
                                table_label=f"project.{script_table_key}",
                                manifest_rel=pyproject_rel,
                                manifest_text=pyproject_text,
                                sp_path=sp_path,
                                sp_files=sp_files,
                                rule_registry=rule_registry,
                                next_id=next_id,
                                findings=findings,
                            )

                    entry_points = project_tbl.get("entry-points")
                    if isinstance(entry_points, dict):
                        is_distributable_package = True
                        for ep_group, ep_tbl in entry_points.items():
                            if isinstance(ep_tbl, dict):
                                self._check_entry_points(
                                    scripts_tbl=ep_tbl,
                                    table_label=f"project.entry-points.{ep_group}",
                                    manifest_rel=pyproject_rel,
                                    manifest_text=pyproject_text,
                                    sp_path=sp_path,
                                    sp_files=sp_files,
                                    rule_registry=rule_registry,
                                    next_id=next_id,
                                    findings=findings,
                                )

            # Validate PEP 735 [dependency-groups]
            if dep_groups_tbl is not None:
                if not isinstance(dep_groups_tbl, dict):
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            observed="[dependency-groups] is not a table",
                            expected="PEP 735 dependency-groups table",
                            file=pyproject_rel,
                            line=find_line_number(pyproject_text, "[dependency-groups]"),
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    for grp_name, grp_items in dep_groups_tbl.items():
                        if str(grp_name).lower() in {"dev", "test", "tests", "lint"}:
                            has_dev_group = True
                        if not isinstance(grp_items, list):
                            continue
                        for item in grp_items:
                            if not isinstance(item, str):
                                continue
                            dep_line = find_line_number(pyproject_text, item)
                            parsed = parse_pep508_requirement(
                                item, line=dep_line, source_file=pyproject_rel
                            )
                            if isinstance(parsed, RequirementParseError):
                                findings.append(
                                    rule_registry.create_finding(
                                        finding_id=next_id(),
                                        rule_id="PY005",
                                        title=f"Invalid dependency in dependency-groups.{grp_name}",
                                        description=parsed.message,
                                        observed=parsed.raw,
                                        expected="Valid PEP 508 dependency string",
                                        file=pyproject_rel,
                                        line=parsed.line,
                                        confidence=Confidence.CONFIRMED,
                                    )
                                )
                            else:
                                all_reqs.append((parsed, f"group:{grp_name}"))

            # Validate Poetry-specific tables
            if is_poetry_project and isinstance(tool_tbl, dict):
                poetry_tbl = tool_tbl["poetry"]
                poetry_deps = poetry_tbl.get("dependencies")
                if isinstance(poetry_deps, dict):
                    for pkg_k, pkg_spec in poetry_deps.items():
                        if str(pkg_k).lower() == "python":
                            py_spec = (
                                pkg_spec
                                if isinstance(pkg_spec, str)
                                else pkg_spec.get("version")
                                if isinstance(pkg_spec, dict)
                                else None
                            )
                            if isinstance(py_spec, str):
                                if declared_python_version is None:
                                    declared_python_version = py_spec
                                    declared_python_file = pyproject_rel
                                    declared_python_line = find_toml_key_line(
                                        pyproject_text, "python", section="tool.poetry.dependencies"
                                    )
                                if not is_valid_poetry_constraint(py_spec):
                                    findings.append(
                                        rule_registry.create_finding(
                                            finding_id=next_id(),
                                            rule_id="PY007",
                                            observed=py_spec,
                                            expected=(
                                                "Valid Poetry/PEP 440 Python version constraint"
                                            ),
                                            file=pyproject_rel,
                                            line=find_toml_key_line(
                                                pyproject_text,
                                                "python",
                                                section="tool.poetry.dependencies",
                                            ),
                                            confidence=Confidence.CONFIRMED,
                                        )
                                    )
                        else:
                            pyproject_direct_pkgs.add(normalize_package_name(str(pkg_k)))

                poetry_groups = poetry_tbl.get("group")
                if isinstance(poetry_groups, dict) and any(
                    str(g).lower() in {"dev", "test"} for g in poetry_groups
                ):
                    has_dev_group = True
                if isinstance(poetry_tbl.get("dev-dependencies"), dict):
                    has_dev_group = True

                poetry_scripts = poetry_tbl.get("scripts")
                if isinstance(poetry_scripts, dict):
                    is_distributable_package = True
                    self._check_entry_points(
                        scripts_tbl=poetry_scripts,
                        table_label="tool.poetry.scripts",
                        manifest_rel=pyproject_rel,
                        manifest_text=pyproject_text,
                        sp_path=sp_path,
                        sp_files=sp_files,
                        rule_registry=rule_registry,
                        next_id=next_id,
                        findings=findings,
                    )

            # Determine if pyproject defines a distributable package lacking [build-system] (PY006)
            if isinstance(project_tbl, dict) and not has_build_system:
                proj_name = project_tbl.get("name")
                has_pkg_init = any(
                    f.endswith("/__init__.py") and not _is_under_non_project_dir(f)
                    for f in sp_files
                )
                if (
                    (is_distributable_package or has_pkg_init)
                    and isinstance(proj_name, str)
                    and not poetry_package_mode_false
                    and not uv_package_false
                    and not is_uv_project
                ):
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY006",
                            observed="Missing [build-system] in distributable pyproject.toml",
                            expected=(
                                "Configured [build-system] table (e.g., hatchling or setuptools)"
                            ),
                            file=pyproject_rel,
                            line=find_line_number(pyproject_text, "[project]"),
                            confidence=Confidence.HIGH,
                        )
                    )

        # 2. Inspect Pipfile
        pipfile_rel = manifests_by_name.get("Pipfile")
        if pipfile_rel is not None:
            pipfile_text, read_err = self._safe_read(pipfile_rel, repo_root, settings)
            if pipfile_text is not None:
                pipfile_data, pf_err, pf_line = parse_toml_safe(pipfile_text)
                if pf_err is not None or pipfile_data is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            title="Invalid Pipfile",
                            description=f"Pipfile contains invalid TOML syntax: {pf_err}",
                            observed=pf_err or "Invalid Pipfile TOML",
                            expected="Valid TOML syntax in Pipfile",
                            file=pipfile_rel,
                            line=pf_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    reqs_tbl = pipfile_data.get("requires")
                    if isinstance(reqs_tbl, dict) and isinstance(
                        reqs_tbl.get("python_version"), str
                    ):
                        py_v = reqs_tbl["python_version"]
                        if declared_python_version is None:
                            declared_python_version = py_v
                            declared_python_file = pipfile_rel
                            declared_python_line = find_toml_key_line(
                                pipfile_text, "python_version", section="requires"
                            )
                        if not is_valid_pep440_specifier(
                            f"=={py_v}.*" if _PYTHON_VERSION_FILE_RE.match(py_v) else py_v
                        ):
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY007",
                                    observed=py_v,
                                    expected="Valid Python version in Pipfile [requires]",
                                    file=pipfile_rel,
                                    line=find_toml_key_line(
                                        pipfile_text, "python_version", section="requires"
                                    ),
                                    confidence=Confidence.CONFIRMED,
                                )
                            )
                    if isinstance(pipfile_data.get("packages"), dict):
                        for pkg_k in pipfile_data["packages"]:
                            pipfile_direct_pkgs.add(normalize_package_name(str(pkg_k)))
                    if (
                        isinstance(pipfile_data.get("dev-packages"), dict)
                        and pipfile_data["dev-packages"]
                    ):
                        has_dev_group = True

        # 3. Inspect setup.cfg
        setup_cfg_rel = manifests_by_name.get("setup.cfg")
        if setup_cfg_rel is not None:
            cfg_text, _ = self._safe_read(setup_cfg_rel, repo_root, settings)
            if cfg_text is not None:
                cfg_parser, cfg_err, cfg_line = parse_setup_cfg_safe(cfg_text)
                if cfg_err is not None or cfg_parser is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            title="Invalid setup.cfg",
                            description=f"setup.cfg could not be parsed: {cfg_err}",
                            observed=cfg_err or "Invalid setup.cfg",
                            expected="Valid INI configuration in setup.cfg",
                            file=setup_cfg_rel,
                            line=cfg_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    if cfg_parser.has_option("options", "python_requires"):
                        py_req = cfg_parser.get("options", "python_requires").strip()
                        if declared_python_version is None:
                            declared_python_version = py_req
                            declared_python_file = setup_cfg_rel
                            declared_python_line = find_line_number(cfg_text, "python_requires")
                    if cfg_parser.has_option("options", "install_requires"):
                        for raw_dep in cfg_parser.get("options", "install_requires").splitlines():
                            cleaned = raw_dep.strip()
                            if not cleaned or cleaned.startswith("#"):
                                continue
                            parsed = parse_pep508_requirement(
                                cleaned,
                                line=find_line_number(cfg_text, cleaned),
                                source_file=setup_cfg_rel,
                            )
                            if isinstance(parsed, RequirementParseError):
                                findings.append(
                                    rule_registry.create_finding(
                                        finding_id=next_id(),
                                        rule_id="PY005",
                                        title="Invalid dependency in setup.cfg",
                                        description=parsed.message,
                                        observed=parsed.raw,
                                        expected="Valid PEP 508 dependency string",
                                        file=setup_cfg_rel,
                                        line=parsed.line,
                                        confidence=Confidence.CONFIRMED,
                                    )
                                )
                            else:
                                all_reqs.append((parsed, "runtime"))
                    if cfg_parser.has_option("options.entry_points", "console_scripts"):
                        ep_map: dict[str, Any] = {}
                        for raw_ep in cfg_parser.get(
                            "options.entry_points", "console_scripts"
                        ).splitlines():
                            if "=" in raw_ep and not raw_ep.strip().startswith("#"):
                                ep_k, ep_v = raw_ep.split("=", 1)
                                ep_map[ep_k.strip()] = ep_v.strip()
                        self._check_entry_points(
                            scripts_tbl=ep_map,
                            table_label="setup.cfg [options.entry_points].console_scripts",
                            manifest_rel=setup_cfg_rel,
                            manifest_text=cfg_text,
                            sp_path=sp_path,
                            sp_files=sp_files,
                            rule_registry=rule_registry,
                            next_id=next_id,
                            findings=findings,
                        )

        # 4. Inspect setup.py statically via AST
        setup_py_rel = manifests_by_name.get("setup.py")
        if setup_py_rel is not None:
            setup_py_text, _ = self._safe_read(setup_py_rel, repo_root, settings)
            if setup_py_text is not None:
                setup_meta = parse_setup_py_static(setup_py_text)
                if setup_meta.syntax_error is not None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY002",
                            title="Invalid Python syntax in setup.py",
                            description=setup_meta.syntax_error,
                            observed=setup_meta.syntax_error,
                            expected="Valid Python syntax in setup.py",
                            file=setup_py_rel,
                            line=setup_meta.syntax_error_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    if setup_meta.python_requires is not None and declared_python_version is None:
                        declared_python_version = setup_meta.python_requires
                        declared_python_file = setup_py_rel
                        declared_python_line = setup_meta.python_requires_line
                    for dep_str, dep_line in setup_meta.install_requires:
                        parsed = parse_pep508_requirement(
                            dep_str, line=dep_line, source_file=setup_py_rel
                        )
                        if isinstance(parsed, RequirementParseError):
                            findings.append(
                                rule_registry.create_finding(
                                    finding_id=next_id(),
                                    rule_id="PY005",
                                    title="Invalid dependency in setup.py install_requires",
                                    description=parsed.message,
                                    observed=parsed.raw,
                                    expected="Valid PEP 508 dependency string",
                                    file=setup_py_rel,
                                    line=parsed.line,
                                    confidence=Confidence.CONFIRMED,
                                )
                            )
                        else:
                            all_reqs.append((parsed, "runtime"))
                    if any(k.lower() in {"dev", "test"} for k in setup_meta.extras_require):
                        has_dev_group = True
                    if setup_meta.console_scripts:
                        ep_map = {name: target for name, target, _ in setup_meta.console_scripts}
                        self._check_entry_points(
                            scripts_tbl=ep_map,
                            table_label="setup.py entry_points.console_scripts",
                            manifest_rel=setup_py_rel,
                            manifest_text=setup_py_text,
                            sp_path=sp_path,
                            sp_files=sp_files,
                            rule_registry=rule_registry,
                            next_id=next_id,
                            findings=findings,
                        )

        # 5. Inspect requirements.txt & requirements-dev.txt (PY009, PY005)
        req_file_reqs: dict[str, list[ParsedRequirement]] = {}
        for req_name in ("requirements.txt", "requirements-dev.txt"):
            req_rel = manifests_by_name.get(req_name)
            if req_rel is None:
                continue
            req_text, _ = self._safe_read(req_rel, repo_root, settings)
            if req_text is None:
                continue
            parsed_reqs, includes, req_errors = parse_requirements_file(
                req_text, source_file=req_rel
            )
            req_file_reqs[req_rel] = parsed_reqs
            group_label = "dev" if req_name == "requirements-dev.txt" else "runtime"
            for pr in parsed_reqs:
                all_reqs.append((pr, group_label))

            for err in req_errors:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="PY009",
                        title=f"Invalid requirement declaration in {req_name}",
                        description=err.message,
                        observed=err.raw,
                        expected="Valid PEP 508 requirement line",
                        file=req_rel,
                        line=err.line,
                        confidence=Confidence.CONFIRMED,
                    )
                )

            for inc in includes:
                req_dir = PurePosixPath(req_rel).parent
                target_rel = (
                    inc.target
                    if req_dir.as_posix() in {"", "."}
                    else f"{req_dir.as_posix()}/{inc.target}"
                )
                try:
                    resolved_inc = validate_within_root(
                        target_rel,
                        repo_root,
                        follow_symlinks=settings.follow_symlinks,
                    )
                    if not resolved_inc.is_file():
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="PY009",
                                title=f"Missing included requirements file in {req_name}",
                                description=(
                                    f"Directive `{inc.kind} {inc.target}` references "
                                    "a file that does not exist."
                                ),
                                observed=inc.target,
                                expected="Existing requirements/constraints file inside repository",
                                file=req_rel,
                                line=inc.line,
                                confidence=Confidence.CONFIRMED,
                            )
                        )
                except DiagoraError:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY009",
                            title=f"Unsafe requirements include path in {req_name}",
                            description=(
                                f"Directive `{inc.kind} {inc.target}` escapes the "
                                "repository boundary or references an invalid path."
                            ),
                            observed=inc.target,
                            expected="Relative path strictly within repository root",
                            file=req_rel,
                            line=inc.line,
                            confidence=Confidence.CONFIRMED,
                            severity=Severity.HIGH,
                        )
                    )

        # 6. Validate Python version declaration (PY001, PY007)
        if declared_python_version is not None:
            is_poetry_only_py = (
                is_poetry_project
                and declared_python_file == pyproject_rel
                and find_toml_key_line(pyproject_text or "", "requires-python", section="project")
                is None
            )
            if (
                not is_poetry_only_py
                and declared_python_file != pipfile_rel
                and not is_valid_pep440_specifier(declared_python_version)
            ):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="PY007",
                        observed=declared_python_version,
                        expected="Valid PEP 440 version constraint (e.g., >=3.10)",
                        file=declared_python_file,
                        line=declared_python_line,
                        confidence=Confidence.CONFIRMED,
                    )
                )
        elif not has_python_version_file and (
            pyproject_valid
            or is_pipenv_project
            or setup_cfg_rel is not None
            or setup_py_rel is not None
        ):
            target_file = pyproject_rel or pipfile_rel or setup_cfg_rel or setup_py_rel
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="PY001",
                    observed="No requires-python, python_requires, .python-version, or runtime.txt",
                    expected=(
                        "Explicit Python version declaration (e.g., requires-python = '>=3.10')"
                    ),
                    file=target_file,
                    confidence=Confidence.CONFIRMED,
                )
            )

        # 7. Check missing lockfiles ONLY when lockfile workflow is configured (PY004)
        if is_poetry_project and "poetry.lock" not in lockfiles_by_name:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="PY004",
                    observed="Poetry configuration ([tool.poetry]) without poetry.lock",
                    expected="Committed poetry.lock for Poetry-managed project",
                    file=pyproject_rel,
                    line=find_line_number(pyproject_text or "", "[tool.poetry]"),
                    confidence=Confidence.HIGH,
                )
            )
        if is_uv_project and "uv.lock" not in lockfiles_by_name:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="PY004",
                    observed="uv configuration ([tool.uv]) without uv.lock",
                    expected="Committed uv.lock for uv-managed project",
                    file=pyproject_rel,
                    line=find_line_number(pyproject_text or "", "[tool.uv]"),
                    confidence=Confidence.HIGH,
                )
            )
        if is_pipenv_project and "Pipfile.lock" not in lockfiles_by_name:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="PY004",
                    observed="Pipfile present without Pipfile.lock",
                    expected="Committed Pipfile.lock for Pipenv-managed project",
                    file=pipfile_rel,
                    confidence=Confidence.HIGH,
                )
            )

        # 8. Lockfile validity & manifest consistency (PY009)
        if "poetry.lock" in lockfiles_by_name:
            pl_rel = lockfiles_by_name["poetry.lock"]
            pl_text, _ = self._safe_read(pl_rel, repo_root, settings)
            if pl_text is not None:
                locked_names, pl_err, pl_line = parse_poetry_lock(pl_text)
                if pl_err is not None or locked_names is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY009",
                            title="Invalid poetry.lock",
                            description=f"poetry.lock could not be parsed: {pl_err}",
                            observed=pl_err or "Invalid poetry.lock",
                            expected="Valid TOML poetry.lock file",
                            file=pl_rel,
                            line=pl_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                elif pyproject_direct_pkgs:
                    missing_locked = sorted(pyproject_direct_pkgs - locked_names)
                    if missing_locked:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="PY009",
                                title="poetry.lock out of sync with pyproject.toml",
                                description=(
                                    "Dependencies declared in pyproject.toml are missing from "
                                    "poetry.lock."
                                ),
                                observed=f"Missing from poetry.lock: {', '.join(missing_locked)}",
                                expected="All declared dependencies locked in poetry.lock",
                                file=pl_rel,
                                confidence=Confidence.CONFIRMED,
                            )
                        )

        if "uv.lock" in lockfiles_by_name:
            ul_rel = lockfiles_by_name["uv.lock"]
            ul_text, _ = self._safe_read(ul_rel, repo_root, settings)
            if ul_text is not None:
                locked_names, ul_err, ul_line = parse_uv_lock(ul_text)
                if ul_err is not None or locked_names is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY009",
                            title="Invalid uv.lock",
                            description=f"uv.lock could not be parsed: {ul_err}",
                            observed=ul_err or "Invalid uv.lock",
                            expected="Valid TOML uv.lock file",
                            file=ul_rel,
                            line=ul_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                elif pyproject_direct_pkgs:
                    missing_locked = sorted(pyproject_direct_pkgs - locked_names)
                    if missing_locked:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="PY009",
                                title="uv.lock out of sync with pyproject.toml",
                                description=(
                                    "Dependencies declared in pyproject.toml are missing from "
                                    "uv.lock."
                                ),
                                observed=f"Missing from uv.lock: {', '.join(missing_locked)}",
                                expected="All declared dependencies locked in uv.lock",
                                file=ul_rel,
                                confidence=Confidence.CONFIRMED,
                            )
                        )

        if "Pipfile.lock" in lockfiles_by_name:
            pfl_rel = lockfiles_by_name["Pipfile.lock"]
            pfl_text, _ = self._safe_read(pfl_rel, repo_root, settings)
            if pfl_text is not None:
                locked_names, pfl_err, pfl_line = parse_pipfile_lock(pfl_text)
                if pfl_err is not None or locked_names is None:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="PY009",
                            title="Invalid Pipfile.lock",
                            description=f"Pipfile.lock contains invalid JSON: {pfl_err}",
                            observed=pfl_err or "Invalid Pipfile.lock",
                            expected="Valid JSON Pipfile.lock file",
                            file=pfl_rel,
                            line=pfl_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                elif pipfile_direct_pkgs:
                    missing_locked = sorted(pipfile_direct_pkgs - locked_names)
                    if missing_locked:
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="PY009",
                                title="Pipfile.lock out of sync with Pipfile",
                                description=(
                                    "Packages declared in Pipfile are missing from Pipfile.lock."
                                ),
                                observed=f"Missing from Pipfile.lock: {', '.join(missing_locked)}",
                                expected="All Pipfile packages locked in Pipfile.lock",
                                file=pfl_rel,
                                confidence=Confidence.CONFIRMED,
                            )
                        )

        # 9. Cross-manifest and intra-manifest dependency conflicts (PY005, PY009)
        self._detect_dependency_conflicts(
            all_reqs=all_reqs,
            rule_registry=rule_registry,
            next_id=next_id,
            findings=findings,
        )

        # 10. Missing dev dependency group when tests exist (PY008)
        has_tests = any(
            PurePosixPath(f).parts
            and (
                "tests" in PurePosixPath(f).parts
                or "test" in PurePosixPath(f).parts
                or PurePosixPath(f).name in _TEST_CONFIG_FILES
            )
            for f in sp_files
        )
        if has_tests and not has_dev_group and (pyproject_valid or is_pipenv_project):
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="PY008",
                    observed="Test suite or test config found without dev/test dependency group",
                    expected=(
                        "Declared dev/test dependencies under [dependency-groups], "
                        "[project.optional-dependencies], or requirements-dev.txt"
                    ),
                    file=pyproject_rel or pipfile_rel,
                    confidence=Confidence.HIGH,
                )
            )

        return findings

    def _check_entry_points(
        self,
        *,
        scripts_tbl: dict[str, Any],
        table_label: str,
        manifest_rel: str,
        manifest_text: str,
        sp_path: str,
        sp_files: list[str],
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        sp_file_set = set(sp_files)
        for ep_name, ep_target in scripts_tbl.items():
            if not isinstance(ep_target, str):
                continue
            target_clean = ep_target.strip()
            line_no = find_line_number(manifest_text, str(ep_name))
            match = _ENTRY_POINT_RE.match(target_clean)
            if not match:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="PY010",
                        observed=f"{ep_name} = {target_clean!r}",
                        expected="Valid Python entry point formatted as `package.module:callable`",
                        details={"section": table_label},
                        file=manifest_rel,
                        line=line_no,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                continue

            module_path = match.group(1)
            rel_module = module_path.replace(".", "/")
            candidates = (
                _join_rel(sp_path, f"{rel_module}.py"),
                _join_rel(sp_path, f"{rel_module}/__init__.py"),
                _join_rel(sp_path, f"src/{rel_module}.py"),
                _join_rel(sp_path, f"src/{rel_module}/__init__.py"),
            )
            if not any(cand in sp_file_set for cand in candidates):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="PY010",
                        observed=f"{ep_name} -> {target_clean} (module not found)",
                        expected=f"Existing module file at {rel_module}.py or src/{rel_module}.py",
                        details={"section": table_label, "checked_paths": list(candidates)},
                        file=manifest_rel,
                        line=line_no,
                        confidence=Confidence.HIGH,
                    )
                )

    def _detect_dependency_conflicts(
        self,
        *,
        all_reqs: list[tuple[ParsedRequirement, str]],
        rule_registry: RuleRegistry,
        next_id: Any,
        findings: list[Finding],
    ) -> None:
        by_pkg: dict[str, list[tuple[ParsedRequirement, str]]] = defaultdict(list)
        for req, grp in all_reqs:
            by_pkg[req.normalized_name].append((req, grp))

        for pkg_name, entries in sorted(by_pkg.items()):
            if len(entries) < 2:
                continue
            # Compare distinct pairs with compatible/empty environment markers
            reported_pairs: set[tuple[str, str]] = set()
            for idx, (req_a, grp_a) in enumerate(entries):
                for req_b, grp_b in entries[idx + 1 :]:
                    if req_a.marker and req_b.marker and req_a.marker != req_b.marker:
                        continue
                    if not specifiers_conflict(req_a.specifier, req_b.specifier):
                        continue
                    pair_sig: tuple[str, str] = (
                        (req_a.raw, req_b.raw) if req_a.raw <= req_b.raw else (req_b.raw, req_a.raw)
                    )
                    if pair_sig in reported_pairs:
                        continue
                    reported_pairs.add(pair_sig)

                    is_req_file_pair = (
                        PurePosixPath(req_a.source_file).name.startswith("requirements")
                        or PurePosixPath(req_b.source_file).name.startswith("requirements")
                    ) and req_a.source_file != req_b.source_file

                    rule_id = "PY009" if is_req_file_pair else "PY005"
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id=rule_id,
                            observed=(
                                f"{pkg_name}: '{req_a.raw}' ({req_a.source_file}) conflicts "
                                f"with '{req_b.raw}' ({req_b.source_file})"
                            ),
                            expected=f"Compatible version constraints for '{pkg_name}'",
                            details={
                                "package": pkg_name,
                                "first": {
                                    "file": req_a.source_file,
                                    "group": grp_a,
                                    "specifier": req_a.specifier,
                                },
                                "second": {
                                    "file": req_b.source_file,
                                    "group": grp_b,
                                    "specifier": req_b.specifier,
                                },
                            },
                            file=req_b.source_file,
                            line=req_b.line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
