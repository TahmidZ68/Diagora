# Diagora Diagnostic Rules Catalog

Every diagnostic finding emitted by Diagora references a stable, versioned rule definition registered in `diagora.rules.registry`.

## Rule Structure

Each rule defines:
- **Rule ID**: Stable identifier (`PYxxx`, `NDxxx`, `ENVxxx`, `DKxxx`, `DPxxx`)
- **Version**: Semantic version of the rule specification
- **Name**: Human-readable title
- **Category**: `python`, `node`, `environment`, `docker`, or `deployment`
- **Default Severity**: `critical`, `high`, `medium`, `low`, or `informational`
- **Status**: `implemented` (active static detection in current release) or `deferred` (registered specification scheduled for a later milestone)
- **Description**: Detailed explanation of what the rule inspects
- **Evidence Requirements**: Required evidence keys (`observed`, `expected`, etc.)
- **Remediation Guidance**: Actionable steps to fix the issue
- **False-Positive Considerations**: Project contexts where the rule does not apply or lowers severity

### Current Implementation Status (`v0.1.0a3`)

- **Implemented (`38` rules)**: `PY001`–`PY010` (`PythonAnalyzer`), `ND001`–`ND009` (`NodeAnalyzer`), `ENV001`–`ENV006` (`EnvironmentAnalyzer`), `DK001`–`DK010` (`DockerAnalyzer`), `DP001`–`DP003` (`DeploymentAnalyzer`).
- **Deferred (`1` rule)**: `ND010` (M3 opt-in runtime probe).

---

## Python Rules (`PY`)

| Rule ID | Name | Default Severity | Description |
| ------- | ---- | ---------------- | ----------- |
| `PY001` | Missing Python version declaration | `medium` | Project does not declare `requires-python` in `pyproject.toml` or a runtime version marker. |
| `PY002` | Invalid `pyproject.toml` | `high` | `pyproject.toml` contains invalid TOML syntax or violates PEP 621 metadata schema. |
| `PY003` | Missing dependency manifest | `medium` | Python source files are present without `pyproject.toml`, `requirements.txt`, `Pipfile`, or `setup.py`. |
| `PY004` | Declared dependency without expected lockfile | `low` | Application dependencies are declared using a lockfile-oriented tool (`poetry`, `uv`, `pipenv`) without the corresponding lockfile. |
| `PY005` | Conflicting dependency declarations | `high` | Incompatible version specifiers for the same package across manifests or dependency groups. |
| `PY006` | Missing build-system configuration | `low` | Distributable package lacks a `[build-system]` table in `pyproject.toml`. |
| `PY007` | Invalid Python version constraint | `high` | Declared Python version specifier cannot be parsed as a valid PEP 440 version constraint. |
| `PY008` | Missing expected development dependency group | `informational` | Project with test suite lacks a declared `dev` or `test` dependency group. |
| `PY009` | Inconsistent requirements files | `medium` | `requirements.txt` and `requirements-dev.txt` (or `pyproject.toml`) define contradictory constraints. |
| `PY010` | Missing package entry point reference | `high` | Console script or module entry point declared in `pyproject.toml` references a nonexistent module path. |

---

## Node.js Rules (`ND`)

| Rule ID | Name | Default Severity | Description |
| ------- | ---- | ---------------- | ----------- |
| `ND001` | Invalid `package.json` | `high` | `package.json` contains malformed JSON or invalid top-level fields. |
| `ND002` | Missing package manager declaration | `informational` | `package.json` does not declare a `packageManager` field (Corepack). |
| `ND003` | Multiple conflicting lockfiles | `high` | Repository root or workspace contains more than one lockfile (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`). |
| `ND004` | Missing Node.js engine requirement | `low` | Project does not specify a Node.js version via `engines.node`, `.nvmrc`, or `.node-version`. |
| `ND005` | Invalid script configuration | `medium` | `scripts` table in `package.json` references missing local binaries or broken script syntax. |
| `ND006` | Missing referenced entry point | `high` | `main`, `module`, `types`, or `bin` field in `package.json` points to a nonexistent file. |
| `ND007` | Workspace configuration inconsistency | `high` | Workspace globs in `package.json` or `pnpm-workspace.yaml` do not match actual workspace packages. |
| `ND008` | TypeScript configuration inconsistency | `medium` | `tsconfig.json` contains invalid JSON/JSONC or references a missing `extends` base file. |
| `ND009` | Lockfile/package manifest mismatch | `high` | Dependencies declared in `package.json` are out of sync with the committed lockfile. |
| `ND010` | Declared runtime package manager unavailable | `medium` | Runtime probe detected that the package manager declared in `package.json` is not installed locally. |

---

## Environment Configuration Rules (`ENV`)

| Rule ID | Name | Default Severity | Description |
| ------- | ---- | ---------------- | ----------- |
| `ENV001` | Missing environment example file | `medium` | Repository references environment variables or `.env` in configuration without providing `.env.example` or `.env.sample`. |
| `ENV002` | Referenced variable absent from example | `medium` | Configuration or Compose file references an environment variable not documented in `.env.example`. |
| `ENV003` | Empty required environment declaration | `medium` | Required environment variable is declared without a value or default fallback where required. |
| `ENV004` | Potential secret committed to repository | `critical` | Tracked configuration or environment template contains a high-entropy secret or private key pattern. |
| `ENV005` | Duplicate or conflicting declarations | `low` | Environment file defines the same variable key multiple times with conflicting values. |
| `ENV006` | Unused example variable | `informational` | Variable in `.env.example` is not referenced by any discovered configuration or source manifest. |

---

## Docker Rules (`DK`)

| Rule ID | Name | Default Severity | Description |
| ------- | ---- | ---------------- | ----------- |
| `DK001` | Missing referenced Dockerfile | `high` | Docker Compose service or deployment configuration references a `Dockerfile` path that does not exist. |
| `DK002` | Invalid build context | `high` | Docker Compose `build.context` directory does not exist or escapes the repository boundary. |
| `DK003` | Invalid Compose configuration | `high` | `docker-compose.yml` or `compose.yaml` contains invalid YAML or violates the Compose specification. |
| `DK004` | Referenced environment file missing | `high` | Compose service `env_file` points to a nonexistent environment file. |
| `DK005` | Port configuration inconsistency | `medium` | Container `EXPOSE` port does not match Compose service port mapping or healthcheck target port. |
| `DK006` | Missing health check | `low` | Critical stateful or backend service in Compose or Dockerfile lacks a `HEALTHCHECK` definition. |
| `DK007` | Undefined Compose service reference | `high` | `depends_on`, `links`, or network configuration references a service not defined in the Compose file. |
| `DK008` | Potentially unsafe privileged configuration | `high` | Compose service enables `privileged: true` or binds the host root filesystem. |
| `DK009` | Suspicious volume mount | `medium` | Compose service mounts a sensitive host directory or nonexistent relative source path. |
| `DK010` | Missing `.dockerignore` | `low` | Repository contains a `Dockerfile` without a `.dockerignore` file, risking context bloat or secret leakage. |

---

## Deployment Rules (`DP`)

| Rule ID | Name | Default Severity | Description |
| ------- | ---- | ---------------- | ----------- |
| `DP001` | Invalid deployment or workflow manifest | `high` | GitHub Actions workflow or `vercel.json` contains malformed YAML/JSON. |
| `DP002` | Missing referenced deployment script or file | `high` | CI workflow or deployment manifest invokes a script or file path that does not exist in the repository. |
| `DP003` | Inconsistent deployment runtime version | `medium` | Runtime version specified in CI/deployment differs from the project's declared Python or Node.js version constraint. |
