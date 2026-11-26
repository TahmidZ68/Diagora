# Diagora CLI Reference

## Synopsis

```bash
diagora [OPTIONS] COMMAND [ARGS]...
```

## Global Options

- `--version`, `-V`: Show the Diagora version and exit.
- `--help`: Show help message and exit.

---

## Commands

### `diagora scan [PATH]`

Discover repository structure, run registered static analyzers, correlate findings, and display a diagnostic report.

**Arguments:**
- `PATH`: Target repository path to scan (default: `.`).

**Options:**
- `--format`, `-f`: Output format: `terminal` (default) or `json`.
- `--severity`, `-s`: Minimum severity threshold to report and enforce (`informational`, `low`, `medium`, `high`, `critical`).
- `--output`, `-o`: Optional file path to write the rendered report.
- `--no-ai`: Disable optional AI root-cause adapter (deterministic mode is already the default).
- `--runtime`: Opt in to safe runtime environment probes (disabled by default).

**Examples:**
```bash
diagora scan .
diagora scan . --format json
diagora scan ./my-repo --severity high
```

---

### `diagora doctor [PATH]`

Perform a repository readiness and local environment health check, summarizing discovered ecosystems, manifests, lockfiles, configuration status, and any critical blockers.

**Arguments:**
- `PATH`: Target repository path (default: `.`).

**Options:**
- `--format`, `-f`: Output format (`terminal` or `json`).
- `--runtime`: Include local runtime tool availability checks.

**Example:**
```bash
diagora doctor .
```

---

### `diagora report [PATH]`

Execute a diagnostic scan and serialize the structured report to disk or stdout.

**Arguments:**
- `PATH`: Target repository path (default: `.`).

**Options:**
- `--output`, `-o`: Destination file path (e.g., `report.json`).
- `--format`, `-f`: Report format (`json` or `terminal`; defaults to `json` when output ends with `.json`).

**Example:**
```bash
diagora report . --output report.json
```

---

### `diagora rules list`

List all registered diagnostic rules in the Diagora rule registry, including whether each rule is `implemented` or `deferred`.

**Options:**
- `--category`, `-c`: Filter rules by category (`python`, `node`, `environment`, `docker`, `deployment`).
- `--status`: Filter rules by implementation status (`implemented`, `deferred`, `all`).
- `--format`, `-f`: Output format (`terminal` or `json`).

**Example:**
```bash
diagora rules list
diagora rules list --status implemented
diagora rules list --category docker
```
