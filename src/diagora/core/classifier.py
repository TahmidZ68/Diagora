"""Project classifier converting discovered files into a structured `RepositoryContext`."""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

from diagora.core.discovery import DiscoveryResult
from diagora.core.models import Ecosystem, RepositoryContext, SubprojectInfo

PYTHON_MANIFEST_NAMES: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "Pipfile",
        "setup.py",
        "setup.cfg",
    }
)

PYTHON_LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
    }
)

PYTHON_CONFIG_NAMES: frozenset[str] = frozenset(
    {
        ".python-version",
        "runtime.txt",
    }
)

NODE_MANIFEST_NAMES: frozenset[str] = frozenset({"package.json"})

NODE_LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
)

NODE_CONFIG_NAMES: frozenset[str] = frozenset(
    {
        ".npmrc",
        ".nvmrc",
        ".node-version",
        "tsconfig.json",
        "pnpm-workspace.yaml",
    }
)

DOCKER_COMPOSE_NAMES: frozenset[str] = frozenset(
    {
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
)

ENV_CONFIG_NAMES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".gitignore",
    }
)

DEPLOYMENT_MANIFEST_NAMES: frozenset[str] = frozenset(
    {
        "vercel.json",
        "render.yaml",
        "fly.toml",
        "railway.json",
        "netlify.toml",
    }
)

UNSUPPORTED_ECOSYSTEM_FILES: frozenset[str] = frozenset(
    {
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "mix.exs",
        "Package.swift",
    }
)

NON_MONOREPO_SUBPROJECT_PREFIXES: tuple[str, ...] = (
    "examples/",
    "example/",
    "docs/",
    "tests/fixtures/",
    "test/fixtures/",
    "fixtures/",
    "samples/",
)


def _is_dockerfile(filename: str) -> bool:
    return (
        filename == "Dockerfile"
        or filename.startswith("Dockerfile.")
        or filename.endswith(".Dockerfile")
    )


def _is_ci_workflow(rel_path: str) -> bool:
    return rel_path.startswith(".github/workflows/") and (
        rel_path.endswith(".yml") or rel_path.endswith(".yaml")
    )


def _is_example_or_fixture_path(rel_dir: str) -> bool:
    if rel_dir in {".", ""}:
        return False
    normalized = f"{rel_dir.strip('/')}/"
    return any(normalized.startswith(prefix) for prefix in NON_MONOREPO_SUBPROJECT_PREFIXES)


class ProjectClassifier:
    """Classifies discovered repository files into ecosystems, manifests, and subprojects."""

    def classify(self, discovery: DiscoveryResult) -> RepositoryContext:
        """Build a normalized `RepositoryContext` from a `DiscoveryResult`."""
        ecosystems: set[Ecosystem] = set()
        package_managers: set[str] = set()
        manifests: list[str] = []
        lockfiles: list[str] = []
        configuration_files: list[str] = []
        docker_files: list[str] = []
        ci_workflows: list[str] = []
        deployment_manifests: list[str] = []
        unsupported_files: list[str] = []

        subproject_manifests: dict[str, list[str]] = defaultdict(list)
        subproject_lockfiles: dict[str, list[str]] = defaultdict(list)
        subproject_configs: dict[str, list[str]] = defaultdict(list)
        subproject_ecosystems: dict[str, set[Ecosystem]] = defaultdict(set)

        for rel_path in discovery.files:
            posix = PurePosixPath(rel_path)
            name = posix.name
            parent_dir = posix.parent.as_posix() if str(posix.parent) != "" else "."

            if _is_example_or_fixture_path(parent_dir) or _is_example_or_fixture_path(rel_path):
                continue

            # 1. Python files
            if name in PYTHON_MANIFEST_NAMES:
                manifests.append(rel_path)
                ecosystems.add(Ecosystem.PYTHON)
                subproject_manifests[parent_dir].append(rel_path)
                subproject_ecosystems[parent_dir].add(Ecosystem.PYTHON)
                if name in {"requirements.txt", "requirements-dev.txt"}:
                    package_managers.add("pip")
                elif name == "Pipfile":
                    package_managers.add("pipenv")

            if name in PYTHON_LOCKFILE_NAMES:
                lockfiles.append(rel_path)
                ecosystems.add(Ecosystem.PYTHON)
                subproject_lockfiles[parent_dir].append(rel_path)
                subproject_ecosystems[parent_dir].add(Ecosystem.PYTHON)
                if name == "uv.lock":
                    package_managers.add("uv")
                elif name == "poetry.lock":
                    package_managers.add("poetry")
                elif name == "Pipfile.lock":
                    package_managers.add("pipenv")

            if name in PYTHON_CONFIG_NAMES:
                configuration_files.append(rel_path)
                ecosystems.add(Ecosystem.PYTHON)
                subproject_configs[parent_dir].append(rel_path)

            if name.endswith(".py") and Ecosystem.PYTHON not in ecosystems:
                ecosystems.add(Ecosystem.PYTHON)

            # 2. Node.js files
            if name in NODE_MANIFEST_NAMES:
                manifests.append(rel_path)
                ecosystems.add(Ecosystem.NODE)
                subproject_manifests[parent_dir].append(rel_path)
                subproject_ecosystems[parent_dir].add(Ecosystem.NODE)

            if name in NODE_LOCKFILE_NAMES:
                lockfiles.append(rel_path)
                ecosystems.add(Ecosystem.NODE)
                subproject_lockfiles[parent_dir].append(rel_path)
                subproject_ecosystems[parent_dir].add(Ecosystem.NODE)
                if name == "package-lock.json":
                    package_managers.add("npm")
                elif name == "pnpm-lock.yaml":
                    package_managers.add("pnpm")
                elif name == "yarn.lock":
                    package_managers.add("yarn")

            if name in NODE_CONFIG_NAMES:
                configuration_files.append(rel_path)
                ecosystems.add(Ecosystem.NODE)
                subproject_configs[parent_dir].append(rel_path)
                if name == "pnpm-workspace.yaml":
                    package_managers.add("pnpm")

            # 3. Docker infrastructure
            if _is_dockerfile(name) or name in DOCKER_COMPOSE_NAMES or name == ".dockerignore":
                docker_files.append(rel_path)
                ecosystems.add(Ecosystem.DOCKER)

            # 4. CI/CD workflows & deployment manifests
            if _is_ci_workflow(rel_path):
                ci_workflows.append(rel_path)
                ecosystems.add(Ecosystem.GITHUB_ACTIONS)

            if name in DEPLOYMENT_MANIFEST_NAMES:
                deployment_manifests.append(rel_path)
                if name == "vercel.json":
                    ecosystems.add(Ecosystem.VERCEL)
                else:
                    ecosystems.add(Ecosystem.GENERIC_DEPLOYMENT)

            # 5. Environment & general configuration
            is_other_config = (
                name.endswith((".yaml", ".yml", ".json", ".toml"))
                and rel_path not in manifests
                and rel_path not in lockfiles
                and rel_path not in docker_files
                and rel_path not in ci_workflows
                and rel_path not in deployment_manifests
                and rel_path not in configuration_files
                and name not in UNSUPPORTED_ECOSYSTEM_FILES
            )
            if name in ENV_CONFIG_NAMES or is_other_config:
                configuration_files.append(rel_path)

            # 6. Unsupported language/project markers
            if name in UNSUPPORTED_ECOSYSTEM_FILES or name.endswith((".csproj", ".sln")):
                unsupported_files.append(rel_path)

        # Infer default package manager when manifest is present without a lockfile
        if (
            Ecosystem.PYTHON in ecosystems
            and not (package_managers & {"uv", "poetry", "pipenv", "pip"})
            and any(m.endswith("pyproject.toml") for m in manifests)
        ):
            package_managers.add("pip")

        if (
            Ecosystem.NODE in ecosystems
            and not (package_managers & {"npm", "pnpm", "yarn"})
            and any(m.endswith("package.json") for m in manifests)
        ):
            package_managers.add("npm")

        # Build subproject inventory excluding nested example/fixture directories
        all_subproject_dirs = sorted(
            set(subproject_manifests.keys()) | set(subproject_lockfiles.keys())
        )
        active_subprojects: list[SubprojectInfo] = []
        non_example_subproject_dirs: list[str] = []

        root_has_workspace_config = any(
            PurePosixPath(c).parent.as_posix() in {".", ""}
            and PurePosixPath(c).name == "pnpm-workspace.yaml"
            for c in configuration_files
        )

        for sub_dir in all_subproject_dirs:
            if _is_example_or_fixture_path(sub_dir):
                continue
            non_example_subproject_dirs.append(sub_dir)
            is_ws_pkg = (
                sub_dir != "."
                and Ecosystem.NODE in subproject_ecosystems[sub_dir]
                and (
                    root_has_workspace_config
                    or sub_dir.startswith(("packages/", "apps/", "libs/", "services/"))
                )
            )
            active_subprojects.append(
                SubprojectInfo(
                    path=sub_dir,
                    ecosystems=sorted(subproject_ecosystems[sub_dir], key=lambda e: e.value),
                    manifests=sorted(subproject_manifests[sub_dir]),
                    lockfiles=sorted(subproject_lockfiles[sub_dir]),
                    config_files=sorted(subproject_configs[sub_dir]),
                    is_workspace_package=is_ws_pkg,
                )
            )

        non_root_subprojects = [d for d in non_example_subproject_dirs if d != "."]
        is_monorepo = len(non_example_subproject_dirs) > 1 or len(non_root_subprojects) > 1

        return RepositoryContext(
            repository_name=discovery.repository_name,
            relative_path=".",
            is_git_repository=discovery.is_git_repository,
            is_monorepo=is_monorepo,
            is_empty=len(discovery.files) == 0,
            detected_ecosystems=sorted(ecosystems, key=lambda e: e.value),
            package_managers=sorted(package_managers),
            manifests=sorted(manifests),
            lockfiles=sorted(lockfiles),
            configuration_files=sorted(configuration_files),
            docker_files=sorted(docker_files),
            ci_workflows=sorted(ci_workflows),
            deployment_manifests=sorted(deployment_manifests),
            unsupported_files=sorted(unsupported_files),
            subprojects=active_subprojects,
            discovered_files=list(discovery.files),
            total_files_inspected=len(discovery.files),
        )
