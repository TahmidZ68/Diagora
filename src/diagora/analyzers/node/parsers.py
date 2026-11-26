"""Safe static parsers for Node.js manifests, lockfiles, workspaces, and TypeScript configs."""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any

import yaml

_NODE_VERSION_RE = re.compile(r"^(?:v?\d+(?:\.\d+)?(?:\.\d+)?|lts/[A-Za-z0-9_*\-]+|node)$")
_PKG_MANAGER_RE = re.compile(r"^(npm|pnpm|yarn|bun)@\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")
_MAJOR_RE = re.compile(r"v?(\d+)")


def parse_json_safe(text: str) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """Safely parse JSON text and require a JSON object at the top level."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, exc.msg, exc.lineno
    except RecursionError:
        return None, "JSON nesting depth exceeds safe parser limits.", 1
    if not isinstance(data, dict):
        return None, f"Expected JSON object at root, got {type(data).__name__}.", 1
    return data, None, None


def strip_jsonc(text: str) -> str:
    """Strip `//` line comments, `/* */` block comments, and trailing commas from JSONC."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False

    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue

        out.append(ch)
        i += 1

    no_comments = "".join(out)
    # Remove trailing commas before closing braces or brackets outside strings
    result: list[str] = []
    j = 0
    m = len(no_comments)
    in_str = False
    esc = False
    while j < m:
        c = no_comments[j]
        if in_str:
            result.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            j += 1
            continue
        if c == '"':
            in_str = True
            result.append(c)
            j += 1
            continue
        if c == ",":
            k = j + 1
            while k < m and no_comments[k] in (" ", "\t", "\r", "\n"):
                k += 1
            if k < m and no_comments[k] in ("}", "]"):
                j += 1
                continue
        result.append(c)
        j += 1
    return "".join(result)


def parse_tsconfig_safe(text: str) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """Safely parse `tsconfig.json` (JSON or JSONC)."""
    cleaned = strip_jsonc(text)
    return parse_json_safe(cleaned)


def find_json_key_line(text: str, key: str) -> int | None:
    """Locate the 1-based line number of a JSON key in source text."""
    pattern = re.compile(rf'^\s*"{re.escape(key)}"\s*:')
    for idx, line in enumerate(text.splitlines(), start=1):
        if pattern.match(line):
            return idx
    return None


def parse_package_manager_field(value: str) -> tuple[str, str] | None:
    """Parse Corepack `packageManager` (`<name>@<semver>`) into `(name, version)`."""
    match = _PKG_MANAGER_RE.match(value.strip())
    if not match:
        return None
    name, version = value.strip().split("@", 1)
    return name, version


def is_valid_node_version_file(text: str) -> tuple[str | None, bool]:
    """Validate `.nvmrc` / `.node-version` content, returning `(value, is_valid)`."""
    lines = [
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
    ]
    if not lines:
        return None, False
    val = lines[0]
    return val, bool(_NODE_VERSION_RE.match(val))


def extract_major_version(spec: str) -> int | None:
    """Extract an unambiguous single major version if present (e.g., 'v20.11.0' -> 20)."""
    cleaned = spec.strip()
    if any(tok in cleaned for tok in ("||", "<", ">", "*", "x", "X", " ")):
        return None
    match = _MAJOR_RE.match(cleaned)
    return int(match.group(1)) if match else None


def engines_allows_major(engines_node: str, major: int) -> bool:
    """Conservative check whether `engines.node` allows `major`; True if ambiguous."""
    cleaned = engines_node.strip()
    if not cleaned or "||" in cleaned:
        return True
    ge_match = re.match(r"^>=\s*v?(\d+)", cleaned)
    if ge_match and "<" not in cleaned:
        return major >= int(ge_match.group(1))
    caret_match = re.match(r"^\^\s*v?(\d+)", cleaned)
    if caret_match:
        return major == int(caret_match.group(1))
    exact_match = re.match(r"^v?(\d+)(?:\.[\dxX*]+)*$", cleaned)
    if exact_match:
        return major == int(exact_match.group(1))
    return True


def parse_pnpm_workspace(text: str) -> tuple[list[str] | None, str | None, int | None]:
    """Safely parse `pnpm-workspace.yaml` and return workspace package globs."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = int(mark.line) + 1 if mark is not None else None
        return None, str(exc), line
    except RecursionError:
        return None, "YAML nesting depth exceeds safe parser limits.", 1
    if not isinstance(data, dict):
        return None, "pnpm-workspace.yaml root must be a YAML mapping.", 1
    packages = data.get("packages")
    if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
        return None, "pnpm-workspace.yaml `packages` must be a list of glob strings.", 1
    return [str(p) for p in packages], None, None


def expand_workspace_patterns(
    patterns: list[str],
    candidate_pkg_dirs: list[str],
    workspace_root: str,
) -> tuple[list[str], list[str]]:
    """Match workspace glob patterns against discovered `package.json` directories.

    Returns `(matched_repo_rel_dirs, unmatched_positive_patterns)`.
    """
    root_prefix = "" if workspace_root in {"", "."} else f"{workspace_root.strip('/')}/"
    rel_dirs: list[str] = []
    for d in candidate_pkg_dirs:
        if d == workspace_root:
            continue
        if root_prefix:
            if d.startswith(root_prefix):
                rel_dirs.append(d[len(root_prefix) :])
        else:
            rel_dirs.append(d)

    positive_patterns: list[str] = []
    negative_patterns: list[str] = []
    for raw in patterns:
        cleaned = raw.strip().replace("\\", "/")
        if not cleaned:
            continue
        if cleaned.startswith("!"):
            negative_patterns.append(cleaned[1:].strip("/"))
        else:
            positive_patterns.append(cleaned.strip("/"))

    matched_rel: set[str] = set()
    unmatched_patterns: list[str] = []

    for pat in positive_patterns:
        pat_norm = pat.rstrip("/")
        hits = [d for d in rel_dirs if fnmatch.fnmatch(d, pat_norm)]
        if not hits:
            unmatched_patterns.append(pat)
        matched_rel.update(hits)

    for neg in negative_patterns:
        neg_norm = neg.rstrip("/")
        matched_rel = {d for d in matched_rel if not fnmatch.fnmatch(d, neg_norm)}

    full_matched = sorted(f"{root_prefix}{d}" if root_prefix else d for d in matched_rel)
    return full_matched, unmatched_patterns


def parse_package_lock(
    text: str,
) -> tuple[dict[str, str] | None, dict[str, str] | None, str | None, int | None]:
    """Parse `package-lock.json` returning `(root_declared_specs, resolved_versions, err, line)`."""
    data, err, line = parse_json_safe(text)
    if err is not None or data is None:
        return None, None, err, line

    lock_version = data.get("lockfileVersion")
    if lock_version is not None and not isinstance(lock_version, int):
        return None, None, "package-lock.json `lockfileVersion` must be an integer.", 1

    root_specs: dict[str, str] = {}
    resolved_versions: dict[str, str] = {}

    packages_tbl = data.get("packages")
    if isinstance(packages_tbl, dict):
        root_entry = packages_tbl.get("")
        if isinstance(root_entry, dict):
            for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
                dep_map = root_entry.get(dep_key)
                if isinstance(dep_map, dict):
                    for pkg_name, spec in dep_map.items():
                        if isinstance(spec, str):
                            root_specs[str(pkg_name)] = spec
        for pkg_path, pkg_meta in packages_tbl.items():
            if not isinstance(pkg_meta, dict) or not pkg_path:
                continue
            if pkg_path.startswith("node_modules/"):
                pkg_name = pkg_path[len("node_modules/") :]
                # Skip nested node_modules inside another package
                if "/node_modules/" not in pkg_name and isinstance(pkg_meta.get("version"), str):
                    resolved_versions[pkg_name] = pkg_meta["version"]

    deps_v1 = data.get("dependencies")
    if isinstance(deps_v1, dict):
        for pkg_name, pkg_meta in deps_v1.items():
            if isinstance(pkg_meta, dict) and isinstance(pkg_meta.get("version"), str):
                resolved_versions.setdefault(str(pkg_name), pkg_meta["version"])

    return root_specs, resolved_versions, None, None


def parse_pnpm_lock(
    text: str,
) -> tuple[dict[str, dict[str, str]] | None, str | None, int | None]:
    """Parse `pnpm-lock.yaml` returning `{importer_path: {pkg_name: specifier}}`."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = int(mark.line) + 1 if mark is not None else None
        return None, str(exc), line
    except RecursionError:
        return None, "pnpm-lock.yaml nesting depth exceeds safe parser limits.", 1
    if not isinstance(data, dict):
        return None, "pnpm-lock.yaml root must be a YAML mapping.", 1

    importers_out: dict[str, dict[str, str]] = {}
    importers = data.get("importers")
    if isinstance(importers, dict):
        for imp_key, imp_val in importers.items():
            if not isinstance(imp_val, dict):
                continue
            pkg_specs: dict[str, str] = {}
            for dep_sec in ("dependencies", "devDependencies", "optionalDependencies"):
                sec_map = imp_val.get(dep_sec)
                if isinstance(sec_map, dict):
                    for pkg_name, entry in sec_map.items():
                        if isinstance(entry, dict) and isinstance(entry.get("specifier"), str):
                            pkg_specs[str(pkg_name)] = entry["specifier"]
                        elif isinstance(entry, str):
                            pkg_specs[str(pkg_name)] = entry
            importers_out[str(imp_key)] = pkg_specs
    else:
        # Older pnpm lockfile v5 single-package format
        root_specs: dict[str, str] = {}
        for dep_sec in ("dependencies", "devDependencies", "optionalDependencies"):
            sec_map = data.get(dep_sec)
            if isinstance(sec_map, dict):
                for pkg_name, spec in sec_map.items():
                    if isinstance(spec, str):
                        root_specs[str(pkg_name)] = spec
                    elif isinstance(spec, dict) and isinstance(spec.get("specifier"), str):
                        root_specs[str(pkg_name)] = spec["specifier"]
        if root_specs:
            importers_out["."] = root_specs

    return importers_out, None, None


def parse_yarn_lock(
    text: str,
) -> tuple[dict[str, set[str]] | None, str | None, int | None]:
    """Parse `yarn.lock` (v1 or Berry) returning `{pkg_name: set_of_locked_specifiers}`."""
    if not text.strip():
        return None, "yarn.lock is empty.", 1

    # Detect Yarn Berry YAML metadata header
    if "__metadata:" in text:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            line = int(mark.line) + 1 if mark is not None else None
            return None, str(exc), line
        except RecursionError:
            return None, "yarn.lock YAML nesting depth exceeds safe parser limits.", 1
        if not isinstance(data, dict):
            return None, "Yarn Berry lockfile must be a YAML mapping.", 1
        locked: dict[str, set[str]] = {}
        for key in data:
            if key == "__metadata":
                continue
            for descriptor in str(key).split(","):
                desc = descriptor.strip().strip('"').strip("'")
                if "@" in desc:
                    at_idx = desc.rfind("@")
                    if at_idx > 0:
                        pkg = desc[:at_idx]
                        spec = desc[at_idx + 1 :]
                        if spec.startswith("npm:"):
                            spec = spec[4:]
                        locked.setdefault(pkg, set()).add(spec)
        return locked, None, None

    # Yarn v1 lockfile line parser
    locked_v1: dict[str, set[str]] = {}
    has_valid_header = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")) and stripped.endswith(":"):
            has_valid_header = True
            header = stripped[:-1]
            for descriptor in header.split(","):
                desc = descriptor.strip().strip('"').strip("'")
                at_idx = desc.rfind("@")
                if at_idx > 0:
                    pkg = desc[:at_idx]
                    spec = desc[at_idx + 1 :]
                    locked_v1.setdefault(pkg, set()).add(spec)

    if not has_valid_header:
        return None, "Unrecognized or malformed yarn.lock format.", 1
    return locked_v1, None, None
