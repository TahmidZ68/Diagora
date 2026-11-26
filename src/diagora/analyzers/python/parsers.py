"""Safe static parsers for Python manifests, requirements, lockfiles, and PEP 440 constraints."""

from __future__ import annotations

import ast
import configparser
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_TOML_LINE_RE = re.compile(r"line\s+(\d+)", re.IGNORECASE)
_SPEC_CLAUSE_RE = re.compile(r"^\s*(===|==|!=|<=|>=|~=|<|>)\s*([A-Za-z0-9][A-Za-z0-9._+\-!*]*)\s*$")
_PEP440_VERSION_RE = re.compile(
    r"^(?:\d+!)?"
    r"\d+(?:\.\d+)*(?:\.\*)?"
    r"(?:(?:a|b|rc)\d+)?"
    r"(?:\.post\d+)?"
    r"(?:\.dev\d+)?"
    r"(?:\+[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?$"
)
_REQ_SPLIT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([^\]]*)\])?(.*)$")
_SIMPLE_NUMERIC_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:\.\*)?$")


@dataclass(frozen=True, slots=True)
class ParsedRequirement:
    """Normalized representation of a Python package requirement."""

    raw: str
    name: str
    normalized_name: str
    specifier: str
    marker: str | None
    line: int | None
    source_file: str


@dataclass(frozen=True, slots=True)
class RequirementInclude:
    """Reference to another requirements or constraints file via `-r` or `-c`."""

    kind: str  # "-r" or "-c"
    target: str
    line: int
    source_file: str


@dataclass(frozen=True, slots=True)
class RequirementParseError:
    """Syntax error encountered while parsing a requirement declaration."""

    raw: str
    message: str
    line: int | None
    source_file: str


@dataclass(slots=True)
class SetupPyMetadata:
    """Statically extracted metadata from `setup.py` via `ast.parse` (never executed)."""

    syntax_error: str | None = None
    syntax_error_line: int | None = None
    has_setup_call: bool = False
    name: str | None = None
    python_requires: str | None = None
    python_requires_line: int | None = None
    install_requires: list[tuple[str, int]] = field(default_factory=list)
    extras_require: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    console_scripts: list[tuple[str, str, int]] = field(default_factory=list)


def normalize_package_name(name: str) -> str:
    """Normalize a Python package name per PEP 503."""
    return _PEP503_NORMALIZE_RE.sub("-", name.strip()).lower()


def parse_toml_safe(text: str) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """Safely parse TOML text without executing code, returning `(data, error, line)`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = str(exc)
        line_match = _TOML_LINE_RE.search(msg)
        line = int(line_match.group(1)) if line_match else None
        return None, msg, line
    except RecursionError:
        return None, "TOML nesting depth exceeds safe parser limits.", 1
    if not isinstance(data, dict):
        return None, "TOML root must be a table.", 1
    return data, None, None


def find_line_number(text: str, needle: str, *, start_line: int = 1) -> int | None:
    """Return the 1-based line number of the first line containing `needle`."""
    lines = text.splitlines()
    for idx in range(max(0, start_line - 1), len(lines)):
        if needle in lines[idx]:
            return idx + 1
    return None


def find_toml_key_line(text: str, key: str, *, section: str | None = None) -> int | None:
    """Locate the 1-based line number of a TOML key, optionally scoped to `[section]`."""
    lines = text.splitlines()
    in_section = section is None
    section_header = f"[{section}]" if section else None
    key_pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if section_header is not None and stripped.startswith("["):
            in_section = stripped == section_header or stripped.startswith(f"[{section}.")
            continue
        if in_section and key_pattern.match(line):
            return idx
    return find_line_number(text, key)


def is_valid_pep440_specifier(spec: str) -> bool:
    """Return True if `spec` is empty or a valid comma-separated PEP 440 specifier."""
    cleaned = spec.strip()
    if not cleaned:
        return True
    # Support parentheses around version specifiers, e.g. (>=3.10,<4.0)
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()
    if not cleaned:
        return False

    clauses = [c.strip() for c in cleaned.split(",")]
    for clause in clauses:
        if not clause:
            return False
        match = _SPEC_CLAUSE_RE.match(clause)
        if not match:
            return False
        op, version = match.groups()
        if not _PEP440_VERSION_RE.match(version):
            return False
        if version.endswith(".*") and op not in {"==", "!="}:
            return False
        if op == "~=" and "." not in version.rstrip(".*"):
            return False
    return True


def is_valid_poetry_constraint(spec: str) -> bool:
    """Validate Poetry caret/tilde/PEP 440 version constraints."""
    cleaned = spec.strip()
    if not cleaned or cleaned == "*":
        return True
    parts = [p.strip() for p in re.split(r"[,|]+", cleaned) if p.strip()]
    if not parts:
        return False
    for part in parts:
        if part == "*":
            continue
        if part[0] in {"^", "~"} and not part.startswith("~="):
            ver = part[1:].strip()
            if not _PEP440_VERSION_RE.match(ver):
                return False
            continue
        if not is_valid_pep440_specifier(part):
            if _PEP440_VERSION_RE.match(part):
                continue
            return False
    return True


def _parse_numeric_tuple(version: str) -> tuple[int, ...] | None:
    match = _SIMPLE_NUMERIC_RE.match(version.strip())
    if not match:
        return None
    parts = tuple(int(p) for p in match.group(1).split("."))
    return parts


def _normalize_tuple_pair(
    a: tuple[int, ...], b: tuple[int, ...]
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    max_len = max(len(a), len(b))
    return (a + (0,) * (max_len - len(a)), b + (0,) * (max_len - len(b)))


def _compare_tuples(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    na, nb = _normalize_tuple_pair(a, b)
    if na < nb:
        return -1
    if na > nb:
        return 1
    return 0


def _extract_numeric_bounds(
    spec: str,
) -> tuple[
    tuple[tuple[int, ...], bool] | None,
    tuple[tuple[int, ...], bool] | None,
    set[tuple[int, ...]],
    bool,
]:
    """Extract conservative `(lower, upper, exact_pins, conflict_within_self)` bounds."""
    cleaned = spec.strip()
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()
    if not cleaned:
        return None, None, set(), False

    lower: tuple[tuple[int, ...], bool] | None = None
    upper: tuple[tuple[int, ...], bool] | None = None
    exact_pins: set[tuple[int, ...]] = set()
    excluded: set[tuple[int, ...]] = set()

    for raw_clause in cleaned.split(","):
        clause = raw_clause.strip()
        if not clause:
            continue
        match = _SPEC_CLAUSE_RE.match(clause)
        if not match:
            return None, None, set(), False
        op, ver_str = match.groups()
        if ver_str.endswith(".*"):
            prefix = _parse_numeric_tuple(ver_str[:-2])
            if prefix is None:
                continue
            if op == "==":
                next_prefix = (*prefix[:-1], prefix[-1] + 1)
                low_cand = (prefix, True)
                up_cand = (next_prefix, False)
                lower = _max_lower(lower, low_cand)
                upper = _min_upper(upper, up_cand)
            continue

        ver = _parse_numeric_tuple(ver_str)
        if ver is None:
            continue

        if op in {"==", "==="}:
            exact_pins.add(_trim_trailing_zeros(ver))
            lower = _max_lower(lower, (ver, True))
            upper = _min_upper(upper, (ver, True))
        elif op == "!=":
            excluded.add(_trim_trailing_zeros(ver))
        elif op == ">=":
            lower = _max_lower(lower, (ver, True))
        elif op == ">":
            lower = _max_lower(lower, (ver, False))
        elif op == "<=":
            upper = _min_upper(upper, (ver, True))
        elif op == "<":
            upper = _min_upper(upper, (ver, False))
        elif op == "~=":
            lower = _max_lower(lower, (ver, True))
            if len(ver) >= 2:
                bump = (*ver[:-2], ver[-2] + 1)
                upper = _min_upper(upper, (bump, False))

    if len(exact_pins) > 1:
        return lower, upper, exact_pins, True
    for pin in exact_pins:
        if pin in excluded:
            return lower, upper, exact_pins, True
    if _bounds_empty(lower, upper):
        return lower, upper, exact_pins, True
    return lower, upper, exact_pins, False


def _trim_trailing_zeros(ver: tuple[int, ...]) -> tuple[int, ...]:
    items = list(ver)
    while len(items) > 1 and items[-1] == 0:
        items.pop()
    return tuple(items)


def _max_lower(
    current: tuple[tuple[int, ...], bool] | None,
    candidate: tuple[tuple[int, ...], bool],
) -> tuple[tuple[int, ...], bool]:
    if current is None:
        return candidate
    cmp = _compare_tuples(current[0], candidate[0])
    if cmp < 0:
        return candidate
    if cmp > 0:
        return current
    return (current[0], current[1] and candidate[1])


def _min_upper(
    current: tuple[tuple[int, ...], bool] | None,
    candidate: tuple[tuple[int, ...], bool],
) -> tuple[tuple[int, ...], bool]:
    if current is None:
        return candidate
    cmp = _compare_tuples(current[0], candidate[0])
    if cmp > 0:
        return candidate
    if cmp < 0:
        return current
    return (current[0], current[1] and candidate[1])


def _bounds_empty(
    lower: tuple[tuple[int, ...], bool] | None,
    upper: tuple[tuple[int, ...], bool] | None,
) -> bool:
    if lower is None or upper is None:
        return False
    cmp = _compare_tuples(lower[0], upper[0])
    if cmp > 0:
        return True
    return bool(cmp == 0 and not (lower[1] and upper[1]))


def specifiers_conflict(spec_a: str, spec_b: str) -> bool:
    """Return True if two PEP 440 specifier strings are deterministically incompatible."""
    if not spec_a.strip() or not spec_b.strip():
        return False
    combined = f"{spec_a.strip()},{spec_b.strip()}"
    _, _, _, conflict = _extract_numeric_bounds(combined)
    return conflict


def parse_pep508_requirement(
    raw: str,
    *,
    line: int | None,
    source_file: str,
) -> ParsedRequirement | RequirementParseError:
    """Parse a PEP 508 dependency declaration string."""
    cleaned = raw.strip()
    if not cleaned:
        return RequirementParseError(
            raw=raw,
            message="Empty dependency declaration.",
            line=line,
            source_file=source_file,
        )

    marker: str | None = None
    req_part = cleaned
    if ";" in cleaned:
        req_part, marker_part = cleaned.split(";", 1)
        req_part = req_part.strip()
        marker = marker_part.strip()
        if not marker:
            return RequirementParseError(
                raw=raw,
                message="Trailing ';' with empty environment marker.",
                line=line,
                source_file=source_file,
            )

    # Direct URL requirement: `pkg @ https://...`
    if " @ " in req_part:
        name_part, url_part = req_part.split(" @ ", 1)
        base_name = name_part.split("[", 1)[0].strip()
        if not _PKG_NAME_RE.match(base_name):
            return RequirementParseError(
                raw=raw,
                message=f"Invalid package name '{base_name}'.",
                line=line,
                source_file=source_file,
            )
        if not url_part.strip():
            return RequirementParseError(
                raw=raw,
                message="Missing URL after '@' in direct reference requirement.",
                line=line,
                source_file=source_file,
            )
        return ParsedRequirement(
            raw=cleaned,
            name=base_name,
            normalized_name=normalize_package_name(base_name),
            specifier="",
            marker=marker,
            line=line,
            source_file=source_file,
        )

    match = _REQ_SPLIT_RE.match(req_part)
    if not match:
        return RequirementParseError(
            raw=raw,
            message=f"Invalid requirement syntax '{req_part}'.",
            line=line,
            source_file=source_file,
        )

    pkg_name, _extras, spec_part = match.groups()
    if not _PKG_NAME_RE.match(pkg_name):
        return RequirementParseError(
            raw=raw,
            message=f"Invalid package name '{pkg_name}'.",
            line=line,
            source_file=source_file,
        )

    spec_clean = spec_part.strip()
    if spec_clean and not is_valid_pep440_specifier(spec_clean):
        return RequirementParseError(
            raw=raw,
            message=f"Invalid version specifier '{spec_clean}' for '{pkg_name}'.",
            line=line,
            source_file=source_file,
        )

    return ParsedRequirement(
        raw=cleaned,
        name=pkg_name,
        normalized_name=normalize_package_name(pkg_name),
        specifier=spec_clean,
        marker=marker,
        line=line,
        source_file=source_file,
    )


def parse_requirements_file(
    text: str,
    *,
    source_file: str,
) -> tuple[list[ParsedRequirement], list[RequirementInclude], list[RequirementParseError]]:
    """Parse a `requirements*.txt` file safely without executing anything."""
    requirements: list[ParsedRequirement] = []
    includes: list[RequirementInclude] = []
    errors: list[RequirementParseError] = []

    raw_lines = text.splitlines()
    idx = 0
    while idx < len(raw_lines):
        start_line = idx + 1
        line = raw_lines[idx]
        # Handle backslash line continuation
        while line.rstrip().endswith("\\") and idx + 1 < len(raw_lines):
            idx += 1
            line = line.rstrip()[:-1] + " " + raw_lines[idx].lstrip()
        idx += 1

        # Strip inline comments preceded by whitespace or at start
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        comment_split = re.split(r"\s+#", stripped, maxsplit=1)
        content = comment_split[0].strip()
        if not content:
            continue

        # Strip --hash=... options attached to a requirement line
        content = re.sub(r"\s+--hash=\S+", "", content).strip()

        # Pip options and include directives
        if content.startswith(("-r ", "--requirement ")):
            target = content.split(None, 1)[1].strip()
            includes.append(
                RequirementInclude(
                    kind="-r",
                    target=target,
                    line=start_line,
                    source_file=source_file,
                )
            )
            continue
        if content.startswith(("-c ", "--constraint ")):
            target = content.split(None, 1)[1].strip()
            includes.append(
                RequirementInclude(
                    kind="-c",
                    target=target,
                    line=start_line,
                    source_file=source_file,
                )
            )
            continue
        if content.startswith("-r") and len(content) > 2:
            includes.append(
                RequirementInclude(
                    kind="-r",
                    target=content[2:].strip(),
                    line=start_line,
                    source_file=source_file,
                )
            )
            continue
        if content.startswith("-c") and len(content) > 2:
            includes.append(
                RequirementInclude(
                    kind="-c",
                    target=content[2:].strip(),
                    line=start_line,
                    source_file=source_file,
                )
            )
            continue

        if content.startswith(
            (
                "-e ",
                "--editable ",
                "-i ",
                "--index-url",
                "--extra-index-url",
                "-f ",
                "--find-links",
                "--trusted-host",
                "--no-binary",
                "--only-binary",
                "--pre",
                "--no-index",
                "--prefer-binary",
                "--require-hashes",
                "--use-pep517",
            )
        ):
            continue

        if content.startswith(("-", "git+", "http://", "https://", "file:", "./", "../", "/")):
            if content.startswith("-") and content not in {"-e", "-r", "-c"}:
                # Unknown flag check
                if content.startswith("--") or len(content) == 2:
                    continue
            else:
                continue

        parsed = parse_pep508_requirement(
            content,
            line=start_line,
            source_file=source_file,
        )
        if isinstance(parsed, RequirementParseError):
            errors.append(parsed)
        else:
            requirements.append(parsed)

    return requirements, includes, errors


def parse_setup_cfg_safe(
    text: str,
) -> tuple[configparser.ConfigParser | None, str | None, int | None]:
    """Parse `setup.cfg` safely with interpolation disabled."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        line = getattr(exc, "lineno", None)
        return None, str(exc), line if isinstance(line, int) and line >= 1 else None
    return parser, None, None


def _ast_literal_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _ast_literal_str_list(node: ast.AST) -> list[tuple[str, int]]:
    items: list[tuple[str, int]] = []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            val = _ast_literal_str(elt)
            if val is not None:
                items.append((val, getattr(elt, "lineno", 1)))
    return items


def parse_setup_py_static(text: str) -> SetupPyMetadata:
    """Statically inspect `setup.py` using `ast.parse` without executing repository code."""
    meta = SetupPyMetadata()
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        meta.syntax_error = exc.msg or "Invalid Python syntax in setup.py."
        meta.syntax_error_line = exc.lineno if exc.lineno and exc.lineno >= 1 else 1
        return meta
    except (RecursionError, ValueError) as exc:
        meta.syntax_error = f"setup.py exceeds safe AST parser limits: {exc}"
        meta.syntax_error_line = 1
        return meta

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name: str | None = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if func_name != "setup":
            continue

        meta.has_setup_call = True
        for kw in node.keywords:
            if kw.arg == "name":
                meta.name = _ast_literal_str(kw.value)
            elif kw.arg == "python_requires":
                meta.python_requires = _ast_literal_str(kw.value)
                meta.python_requires_line = getattr(kw.value, "lineno", None)
            elif kw.arg == "install_requires":
                meta.install_requires.extend(_ast_literal_str_list(kw.value))
            elif kw.arg == "extras_require" and isinstance(kw.value, ast.Dict):
                for k_node, v_node in zip(kw.value.keys, kw.value.values, strict=False):
                    if k_node is None:
                        continue
                    k_str = _ast_literal_str(k_node)
                    if k_str is not None:
                        meta.extras_require[k_str] = _ast_literal_str_list(v_node)
            elif kw.arg == "entry_points" and isinstance(kw.value, ast.Dict):
                for k_node, v_node in zip(kw.value.keys, kw.value.values, strict=False):
                    if k_node is None:
                        continue
                    if _ast_literal_str(k_node) == "console_scripts":
                        for entry_str, entry_line in _ast_literal_str_list(v_node):
                            if "=" in entry_str:
                                ep_name, ep_target = entry_str.split("=", 1)
                                meta.console_scripts.append(
                                    (ep_name.strip(), ep_target.strip(), entry_line)
                                )
        break

    return meta


def parse_poetry_lock(text: str) -> tuple[set[str] | None, str | None, int | None]:
    """Parse `poetry.lock` (TOML) and return normalized locked package names."""
    data, err, line = parse_toml_safe(text)
    if err is not None or data is None:
        return None, err, line
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return None, "poetry.lock `package` entry must be a list of tables.", 1
    names: set[str] = set()
    for pkg in packages:
        if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
            names.add(normalize_package_name(pkg["name"]))
    return names, None, None


def parse_uv_lock(text: str) -> tuple[set[str] | None, str | None, int | None]:
    """Parse `uv.lock` (TOML) and return normalized locked package names."""
    data, err, line = parse_toml_safe(text)
    if err is not None or data is None:
        return None, err, line
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return None, "uv.lock `package` entry must be a list of tables.", 1
    names: set[str] = set()
    for pkg in packages:
        if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
            names.add(normalize_package_name(pkg["name"]))
    return names, None, None


def parse_pipfile_lock(text: str) -> tuple[set[str] | None, str | None, int | None]:
    """Parse `Pipfile.lock` (JSON) and return normalized locked package names."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, exc.msg, exc.lineno
    except RecursionError:
        return None, "Pipfile.lock JSON nesting depth exceeds safe parser limits.", 1
    if not isinstance(data, dict):
        return None, "Pipfile.lock root must be a JSON object.", 1
    names: set[str] = set()
    for section in ("default", "develop"):
        sec_val = data.get(section, {})
        if isinstance(sec_val, dict):
            for pkg_name in sec_val:
                names.add(normalize_package_name(str(pkg_name)))
    return names, None, None
