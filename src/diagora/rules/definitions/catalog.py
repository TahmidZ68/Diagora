"""Built-in catalog of initial Diagora diagnostic rule specifications."""

from __future__ import annotations

from diagora.core.models import Category, Severity
from diagora.rules.registry import RuleDefinition, RuleRegistry

INITIAL_RULES: tuple[RuleDefinition, ...] = (
    # Python Rules (PY001 - PY010)
    RuleDefinition(
        rule_id="PY001",
        name="Missing Python version declaration",
        description=(
            "Python project does not specify a required Python version constraint "
            "in pyproject.toml or a runtime version file."
        ),
        category=Category.PYTHON,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            'Add `requires-python = ">=3.10"` under `[project]` in pyproject.toml.'
        ),
        test_fixtures=["python/missing_requires_python"],
        false_positive_considerations=(
            "Single-file utility scripts without packaging metadata may not "
            "require a version constraint."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY002",
        name="Invalid pyproject.toml",
        description=(
            "The pyproject.toml manifest contains malformed TOML syntax "
            "or invalid PEP 621 metadata types."
        ),
        category=Category.PYTHON,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Fix syntax errors in pyproject.toml and ensure `[project]` fields adhere to PEP 621."
        ),
        test_fixtures=["python/malformed_pyproject"],
        false_positive_considerations=(
            "None; malformed TOML always breaks Python build and packaging tools."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY003",
        name="Missing dependency manifest",
        description=(
            "Python source files were discovered without any recognized dependency "
            "manifest (pyproject.toml, requirements.txt, Pipfile, setup.py)."
        ),
        category=Category.PYTHON,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Create a pyproject.toml or requirements.txt declaring project dependencies."
        ),
        test_fixtures=["python/no_manifest"],
        false_positive_considerations=(
            "Standard-library-only scripts or doc snippet folders may not "
            "need a dependency manifest."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY004",
        name="Declared dependency without expected lockfile",
        description=(
            "Project configures a lockfile-based workflow (Poetry, uv, Pipenv) "
            "but the expected lockfile is absent."
        ),
        category=Category.PYTHON,
        default_severity=Severity.LOW,
        remediation_guidance=(
            "Generate and commit the lockfile (e.g., `uv lock` or `poetry lock`) "
            "for reproducible builds."
        ),
        test_fixtures=["python/missing_lockfile"],
        false_positive_considerations=(
            "Reusable Python libraries published to PyPI intentionally omit lockfiles."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY005",
        name="Conflicting dependency declarations",
        description=(
            "Mutually exclusive version constraints are declared for the same Python package."
        ),
        category=Category.PYTHON,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Align package version constraints across dependency tables and requirements files."
        ),
        test_fixtures=["python/conflicting_deps"],
        false_positive_considerations=(
            "Platform-specific environment markers targeting disjoint OS or Python versions."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY006",
        name="Missing build-system configuration",
        description=(
            "Distributable Python package pyproject.toml omits the `[build-system]` table."
        ),
        category=Category.PYTHON,
        default_severity=Severity.LOW,
        remediation_guidance=(
            "Add a `[build-system]` section (e.g., Hatchling, Setuptools, Flit) to pyproject.toml."
        ),
        test_fixtures=["python/missing_build_system"],
        false_positive_considerations=(
            "Non-packaged application projects managed purely as virtual environments "
            "may omit `[build-system]`."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY007",
        name="Invalid Python version constraint",
        description=(
            "The declared `requires-python` or Python version specifier is not "
            "a valid PEP 440 specifier."
        ),
        category=Category.PYTHON,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Replace the version string with a valid PEP 440 specifier such as `>=3.10,<4.0`."
        ),
        test_fixtures=["python/invalid_version_spec"],
        false_positive_considerations=(
            "None; invalid PEP 440 constraints are rejected by pip and build backends."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY008",
        name="Missing expected development dependency group",
        description=(
            "Repository contains a `tests/` directory or linter config without "
            "a declared `dev` or `test` dependency group."
        ),
        category=Category.PYTHON,
        default_severity=Severity.INFORMATIONAL,
        remediation_guidance=(
            "Define `[dependency-groups]` or `[project.optional-dependencies]` "
            "for test and linting tools."
        ),
        test_fixtures=["python/missing_dev_group"],
        false_positive_considerations=(
            "Projects executing tests exclusively via global CI containers."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY009",
        name="Inconsistent requirements files",
        description=(
            "Multiple requirements files or manifests specify divergent pins "
            "for shared dependencies."
        ),
        category=Category.PYTHON,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Consolidate shared dependencies or reference base requirements "
            "via `-r requirements.txt`."
        ),
        test_fixtures=["python/inconsistent_requirements"],
        false_positive_considerations=(
            "Intentional compatibility matrix testing across multiple pinned files."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="PY010",
        name="Missing package entry point reference",
        description=(
            "A script or entry point in pyproject.toml references a Python module "
            "path that does not exist in the repository."
        ),
        category=Category.PYTHON,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Update `[project.scripts]` to match the actual package directory and module name."
        ),
        test_fixtures=["python/missing_entrypoint"],
        false_positive_considerations=(
            "Dynamically generated modules created during custom build hooks."
        ),
        implemented=True,
    ),
    # Node.js Rules (ND001 - ND010)
    RuleDefinition(
        rule_id="ND001",
        name="Invalid package.json",
        description=(
            "The package.json file contains invalid JSON syntax or violates required schema types."
        ),
        category=Category.NODE,
        default_severity=Severity.HIGH,
        remediation_guidance="Fix JSON syntax errors in package.json.",
        test_fixtures=["node/invalid_package_json"],
        false_positive_considerations="None; malformed JSON breaks all Node.js package managers.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND002",
        name="Missing package manager declaration",
        description="package.json does not specify a Corepack `packageManager` field.",
        category=Category.NODE,
        default_severity=Severity.INFORMATIONAL,
        remediation_guidance=(
            'Add `"packageManager": "pnpm@9.0.0"` (or npm/yarn version) to package.json.'
        ),
        test_fixtures=["node/missing_package_manager"],
        false_positive_considerations=(
            "Projects that do not use Corepack and rely solely on a committed lockfile."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND003",
        name="Multiple conflicting lockfiles",
        description=(
            "Multiple Node.js lockfiles (package-lock.json, pnpm-lock.yaml, yarn.lock) "
            "exist in the same project root."
        ),
        category=Category.NODE,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Remove redundant lockfiles and retain only the lockfile for your "
            "active package manager."
        ),
        test_fixtures=["node/multiple_lockfiles"],
        false_positive_considerations="None within the same package root.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND004",
        name="Missing Node.js engine requirement",
        description=(
            "Project does not declare a required Node.js runtime version via "
            "`engines.node`, `.nvmrc`, or `.node-version`."
        ),
        category=Category.NODE,
        default_severity=Severity.LOW,
        remediation_guidance=(
            'Specify `"engines": { "node": ">=20" }` in package.json or add an `.nvmrc` file.'
        ),
        test_fixtures=["node/missing_engine"],
        false_positive_considerations=(
            "Isomorphic browser-only utility libraries with no Node runtime dependency."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND005",
        name="Invalid script configuration",
        description=(
            "A script in `package.json` references a nonexistent relative script "
            "file or empty command."
        ),
        category=Category.NODE,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Update the script command in `package.json` to reference a valid file or binary."
        ),
        test_fixtures=["node/invalid_script"],
        false_positive_considerations=(
            "Scripts referencing artifacts generated by a prior build step."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND006",
        name="Missing referenced entry point",
        description=(
            "The `main`, `module`, `types`, or `bin` target declared in "
            "package.json does not exist."
        ),
        category=Category.NODE,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Ensure the entry point path in package.json matches the source "
            "or compiled output layout."
        ),
        test_fixtures=["node/missing_entrypoint"],
        false_positive_considerations=(
            "TypeScript projects before `dist/` has been built (lower confidence "
            "if `tsconfig.json` `outDir` matches)."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND007",
        name="Workspace configuration inconsistency",
        description=(
            "Workspace patterns in package.json or pnpm-workspace.yaml do not "
            "match any valid package directories."
        ),
        category=Category.NODE,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Align `workspaces` globs with the actual subpackage directories "
            "containing package.json."
        ),
        test_fixtures=["node/broken_workspaces"],
        false_positive_considerations="Newly scaffolded monorepo before packages are added.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND008",
        name="TypeScript configuration inconsistency",
        description=(
            "tsconfig.json cannot be parsed or its `extends` path references "
            "a missing configuration file."
        ),
        category=Category.NODE,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Fix tsconfig.json syntax or restore the referenced base configuration file."
        ),
        test_fixtures=["node/invalid_tsconfig"],
        false_positive_considerations=(
            "Base config provided by an uninstalled `node_modules` package during static scan."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND009",
        name="Lockfile/package manifest mismatch",
        description=(
            "Dependencies declared in package.json are missing from or conflict "
            "with the committed lockfile."
        ),
        category=Category.NODE,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Run your package manager install command to synchronize the "
            "lockfile with package.json."
        ),
        test_fixtures=["node/lockfile_mismatch"],
        false_positive_considerations=(
            "None; out-of-sync lockfiles cause `npm ci` or `--frozen-lockfile` failures in CI."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ND010",
        name="Declared runtime package manager unavailable",
        description=(
            "The package manager required by the project is not installed or "
            "accessible in the current runtime environment."
        ),
        category=Category.NODE,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Enable Corepack (`corepack enable`) or install the declared package manager globally."
        ),
        test_fixtures=["node/runtime_pm_unavailable"],
        false_positive_considerations=(
            "Only applicable when `--runtime` diagnostics are explicitly enabled."
        ),
    ),
    # Environment Configuration Rules (ENV001 - ENV006)
    RuleDefinition(
        rule_id="ENV001",
        name="Missing environment example file",
        description=(
            "Project configuration references environment variables or `.env` files, "
            "but no `.env.example` or `.env.sample` is present."
        ),
        category=Category.ENVIRONMENT,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Add a `.env.example` file documenting required environment variables "
            "with safe placeholder values."
        ),
        test_fixtures=["env/missing_env_example"],
        false_positive_considerations="Projects that require zero runtime environment variables.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ENV002",
        name="Referenced variable absent from example",
        description=(
            "An environment variable referenced in Compose or application config "
            "is missing from `.env.example`."
        ),
        category=Category.ENVIRONMENT,
        default_severity=Severity.MEDIUM,
        remediation_guidance="Document the missing environment variable key in `.env.example`.",
        test_fixtures=["env/undocumented_var"],
        false_positive_considerations=(
            "Standard system variables (e.g., `PATH`, `HOME`, `CI`) do not "
            "belong in `.env.example`."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ENV003",
        name="Empty required environment declaration",
        description=(
            "A required environment variable is declared without a value or fallback default."
        ),
        category=Category.ENVIRONMENT,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Provide a safe development default or document how to populate the required variable."
        ),
        test_fixtures=["env/empty_required_var"],
        false_positive_considerations=(
            "Variables intentionally left blank in `.env.example` for user-supplied secrets."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ENV004",
        name="Potential secret committed to repository",
        description=(
            "A tracked configuration or environment example file appears to "
            "contain a live credential or private key."
        ),
        category=Category.ENVIRONMENT,
        default_severity=Severity.CRITICAL,
        remediation_guidance=(
            "Rotate the exposed credential immediately and replace the value "
            "with a dummy placeholder."
        ),
        test_fixtures=["env/committed_secret"],
        false_positive_considerations="Well-known test tokens or explicitly marked mock fixtures.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ENV005",
        name="Duplicate or conflicting declarations",
        description=(
            "The same environment variable key is defined multiple times with "
            "conflicting values in an environment file."
        ),
        category=Category.ENVIRONMENT,
        default_severity=Severity.LOW,
        remediation_guidance=(
            "Remove duplicate environment variable keys so only a single "
            "canonical definition remains."
        ),
        test_fixtures=["env/duplicate_keys"],
        false_positive_considerations="None; duplicate keys lead to silent override behavior.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="ENV006",
        name="Unused example variable",
        description=(
            "An environment variable declared in `.env.example` is not referenced "
            "in any discovered configuration file."
        ),
        category=Category.ENVIRONMENT,
        default_severity=Severity.INFORMATIONAL,
        remediation_guidance=(
            "Verify whether the variable is still used by application code "
            "or remove stale declarations."
        ),
        test_fixtures=["env/unused_example_var"],
        false_positive_considerations=(
            "Variables consumed dynamically by application code not scanned "
            "by static config parsers."
        ),
        implemented=True,
    ),
    # Docker Rules (DK001 - DK010)
    RuleDefinition(
        rule_id="DK001",
        name="Missing referenced Dockerfile",
        description=(
            "A Compose service or build configuration references a Dockerfile "
            "path that does not exist."
        ),
        category=Category.DOCKER,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Update the `dockerfile` path or create the missing Dockerfile "
            "at the referenced location."
        ),
        test_fixtures=["docker/missing_dockerfile"],
        false_positive_considerations="None; `docker compose build` will deterministically fail.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK002",
        name="Invalid build context",
        description=(
            "The Docker build context directory specified in Compose does not "
            "exist or escapes the repository root."
        ),
        category=Category.DOCKER,
        default_severity=Severity.HIGH,
        remediation_guidance="Set `build.context` to an existing directory inside the repository.",
        test_fixtures=["docker/invalid_build_context"],
        false_positive_considerations="None; an invalid build context prevents image builds.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK003",
        name="Invalid Compose configuration",
        description=(
            "The Docker Compose file contains malformed YAML or invalid "
            "top-level service structure."
        ),
        category=Category.DOCKER,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Fix YAML syntax and ensure services follow the Compose specification."
        ),
        test_fixtures=["docker/invalid_compose"],
        false_positive_considerations="None.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK004",
        name="Referenced environment file missing",
        description=(
            "A Compose service `env_file` directive references a file that "
            "does not exist in the repository."
        ),
        category=Category.DOCKER,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Create the referenced `.env` file (e.g., from `.env.example`) "
            "or mark `required: false` in Compose."
        ),
        test_fixtures=["docker/missing_env_file"],
        false_positive_considerations=(
            "Local `.env` files that are gitignored and expected to be created during onboarding."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK005",
        name="Port configuration inconsistency",
        description=(
            "Dockerfile `EXPOSE` port does not match the container target "
            "port mapped in Docker Compose."
        ),
        category=Category.DOCKER,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Align the container port in Compose `ports` with the port exposed "
            "by the Dockerfile and application."
        ),
        test_fixtures=["docker/port_mismatch"],
        false_positive_considerations=(
            "Multi-stage Dockerfiles where different stages expose different ports."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK006",
        name="Missing health check",
        description=(
            "A container service in Docker Compose or Dockerfile does not define a health check."
        ),
        category=Category.DOCKER,
        default_severity=Severity.LOW,
        remediation_guidance=(
            "Add a `healthcheck` block to the Compose service or `HEALTHCHECK` "
            "instruction in the Dockerfile."
        ),
        test_fixtures=["docker/missing_healthcheck"],
        false_positive_considerations=(
            "One-shot migration jobs or CLI utility containers that exit after completion."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK007",
        name="Undefined Compose service reference",
        description=(
            "A service's `depends_on` or `links` references a service name "
            "that is not defined in the Compose file."
        ),
        category=Category.DOCKER,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Update `depends_on` to reference a valid service defined under `services:`."
        ),
        test_fixtures=["docker/undefined_service_ref"],
        false_positive_considerations=(
            "Multi-file Compose setups where the base service is defined in an override file."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK008",
        name="Potentially unsafe privileged configuration",
        description="Compose service enables `privileged: true` or sensitive host namespaces.",
        category=Category.DOCKER,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Remove `privileged: true` and grant only specific Linux capabilities "
            "via `cap_add` if needed."
        ),
        test_fixtures=["docker/privileged_container"],
        false_positive_considerations=(
            "Specialized system or Docker-in-Docker runner containers that "
            "explicitly require host privileges."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK009",
        name="Suspicious volume mount",
        description=(
            "Compose service mounts a sensitive host path (e.g., `/`, `/etc`, "
            "`/var/run/docker.sock`) or path escaping repository."
        ),
        category=Category.DOCKER,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Scope volume bind mounts to project subdirectories or named Docker volumes."
        ),
        test_fixtures=["docker/suspicious_volume"],
        false_positive_considerations=(
            "Local reverse proxies (e.g., Traefik) that intentionally read `/var/run/docker.sock`."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DK010",
        name="Missing .dockerignore",
        description="Repository contains a Dockerfile without a `.dockerignore` file.",
        category=Category.DOCKER,
        default_severity=Severity.LOW,
        remediation_guidance=(
            "Create a `.dockerignore` excluding `.git`, `.venv`, `node_modules`, and `.env` files."
        ),
        test_fixtures=["docker/missing_dockerignore"],
        false_positive_considerations=(
            "Isolated subdirectory build contexts that contain only a binary and Dockerfile."
        ),
        implemented=True,
    ),
    # Deployment Rules (DP001 - DP003)
    RuleDefinition(
        rule_id="DP001",
        name="Invalid deployment or workflow manifest",
        description=(
            "A GitHub Actions workflow or deployment manifest (`vercel.json`) "
            "contains invalid YAML/JSON syntax."
        ),
        category=Category.DEPLOYMENT,
        default_severity=Severity.HIGH,
        remediation_guidance="Fix syntax errors in the workflow or deployment manifest.",
        test_fixtures=["deployment/invalid_workflow_yaml"],
        false_positive_considerations="None.",
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DP002",
        name="Missing referenced deployment script or file",
        description=(
            "A CI workflow or deployment manifest references a local script "
            "or configuration path that does not exist."
        ),
        category=Category.DEPLOYMENT,
        default_severity=Severity.HIGH,
        remediation_guidance=(
            "Restore the missing script file or update the path in the "
            "workflow/deployment configuration."
        ),
        test_fixtures=["deployment/missing_workflow_script"],
        false_positive_considerations=(
            "Files generated dynamically during an earlier step in the same CI job."
        ),
        implemented=True,
    ),
    RuleDefinition(
        rule_id="DP003",
        name="Inconsistent deployment runtime version",
        description=(
            "The Python or Node.js version configured in CI/deployment conflicts "
            "with the version declared in project manifests."
        ),
        category=Category.DEPLOYMENT,
        default_severity=Severity.MEDIUM,
        remediation_guidance=(
            "Align the CI workflow or `vercel.json` runtime version with "
            "`pyproject.toml` / `package.json`."
        ),
        test_fixtures=["deployment/runtime_version_mismatch"],
        false_positive_considerations=(
            "Multi-version CI test matrices that intentionally test older and newer runtimes."
        ),
        implemented=True,
    ),
)


def build_default_rule_registry() -> RuleRegistry:
    """Create a `RuleRegistry` populated with all built-in Diagora rules."""
    registry = RuleRegistry()
    registry.register_many(INITIAL_RULES)
    return registry
