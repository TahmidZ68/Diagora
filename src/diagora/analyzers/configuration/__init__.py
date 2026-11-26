"""Shared structured configuration (YAML, JSON, TOML, and .env) parsers for M2 analyzers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from diagora.analyzers.node.parsers import parse_json_safe
from diagora.analyzers.python.parsers import parse_toml_safe

_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


@dataclass(frozen=True, slots=True)
class EnvEntry:
    """Single parsed environment variable assignment from a dotenv-style file."""

    key: str
    value: str
    has_value: bool
    line: int
    comment: str = ""


def parse_yaml_safe(text: str) -> tuple[Any | None, str | None, int | None]:
    """Safely parse YAML text using `yaml.safe_load` with RecursionError protection."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        line = 1
        mark = getattr(exc, "problem_mark", None)
        if mark is not None and getattr(mark, "line", None) is not None:
            line = int(mark.line) + 1
        return None, str(exc), line
    except RecursionError:
        return None, "YAML nesting depth exceeds safe parser limits.", 1
    return data, None, None


def find_yaml_key_line(text: str, key: str, start_line: int = 1) -> int | None:
    """Locate the first 1-based line defining a YAML mapping key at or after `start_line`."""
    pattern = re.compile(rf"^\s*-?\s*{re.escape(key)}\s*:")
    lines = text.splitlines()
    for idx in range(max(1, start_line), len(lines) + 1):
        if pattern.match(lines[idx - 1]):
            return idx
    return None


def _split_env_value_and_comment(raw_rhs: str) -> tuple[str, str]:
    """Extract normalized unquoted value and trailing comment from dotenv RHS."""
    stripped = raw_rhs.strip()
    if not stripped:
        return "", ""

    if stripped[0] in {"'", '"'}:
        quote = stripped[0]
        escaped = False
        chars: list[str] = []
        idx = 1
        while idx < len(stripped):
            ch = stripped[idx]
            if escaped:
                chars.append(ch)
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                rest = stripped[idx + 1 :].strip()
                comment = rest[1:].strip() if rest.startswith("#") else ""
                return "".join(chars), comment
            else:
                chars.append(ch)
            idx += 1
        return stripped.strip(quote), ""

    if " #" in stripped:
        val_part, comment_part = stripped.split(" #", 1)
        return val_part.strip(), comment_part.strip()
    if stripped.startswith("#"):
        return "", stripped[1:].strip()
    return stripped, ""


def parse_env_file(text: str) -> list[EnvEntry]:
    """Parse dotenv-style files into ordered `EnvEntry` records preserving line numbers."""
    entries: list[EnvEntry] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(stripped)
        if not match:
            continue
        key, raw_rhs = match.group(1), match.group(2)
        value, comment = _split_env_value_and_comment(raw_rhs)
        entries.append(
            EnvEntry(
                key=key,
                value=value,
                has_value=bool(value),
                line=line_no,
                comment=comment,
            )
        )
    return entries


__all__ = [
    "EnvEntry",
    "find_yaml_key_line",
    "parse_env_file",
    "parse_json_safe",
    "parse_toml_safe",
    "parse_yaml_safe",
]
