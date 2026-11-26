"""Safe static parsers for Dockerfiles, Compose files, port specs, and volume mounts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_PORT_NUMBER_RE = re.compile(r"^(\d+)(?:/(?:tcp|udp))?$")
_HOST_BIND_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[/.~])")


@dataclass(frozen=True, slots=True)
class ParsedDockerfile:
    """Static metadata extracted from a Dockerfile."""

    rel_path: str
    exposed_ports: list[tuple[int, int]] = field(default_factory=list)
    has_healthcheck: bool = False
    base_images: list[tuple[str, int]] = field(default_factory=list)


def _iter_dockerfile_instructions(text: str) -> list[tuple[int, str]]:
    """Join backslash line continuations and yield `(start_line, instruction_text)` pairs."""
    instructions: list[tuple[int, str]] = []
    lines = text.splitlines()
    buf: list[str] = []
    start_line: int | None = None

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not buf:
            if not stripped or stripped.startswith("#"):
                continue
            start_line = idx
        elif stripped.startswith("#"):
            continue

        if stripped.endswith("\\"):
            buf.append(stripped[:-1].rstrip())
            continue

        buf.append(stripped)
        if start_line is not None:
            joined = " ".join(part for part in buf if part).strip()
            if joined:
                instructions.append((start_line, joined))
        buf.clear()
        start_line = None

    if buf and start_line is not None:
        joined = " ".join(part for part in buf if part).strip()
        if joined:
            instructions.append((start_line, joined))

    return instructions


def parse_dockerfile(text: str, rel_path: str) -> ParsedDockerfile:
    """Parse static instructions (`FROM`, `EXPOSE`, `HEALTHCHECK`) from Dockerfile text."""
    exposed_ports: list[tuple[int, int]] = []
    has_healthcheck = False
    base_images: list[tuple[str, int]] = []

    for line_no, stmt in _iter_dockerfile_instructions(text):
        parts = stmt.split(None, 1)
        if not parts:
            continue
        keyword = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if keyword == "FROM" and rest:
            image_ref = rest.split()[0]
            base_images.append((image_ref, line_no))
        elif keyword == "EXPOSE" and rest:
            for token in rest.split():
                match = _PORT_NUMBER_RE.match(token.strip())
                if match:
                    exposed_ports.append((int(match.group(1)), line_no))
        elif keyword == "HEALTHCHECK" and not rest.upper().startswith("NONE"):
            has_healthcheck = True

    return ParsedDockerfile(
        rel_path=rel_path,
        exposed_ports=exposed_ports,
        has_healthcheck=has_healthcheck,
        base_images=base_images,
    )


def extract_compose_container_ports(ports_value: Any) -> list[int]:
    """Extract target container port numbers from Compose `ports` list entries."""
    if not isinstance(ports_value, list):
        return []
    result: list[int] = []
    for item in ports_value:
        if isinstance(item, int):
            result.append(item)
            continue
        if isinstance(item, dict):
            target = item.get("target")
            if isinstance(target, int):
                result.append(target)
            elif isinstance(target, str) and target.isdigit():
                result.append(int(target))
            continue
        if isinstance(item, str):
            cleaned = item.strip().strip("\"'")
            # Strip protocol suffix like /tcp
            cleaned = cleaned.split("/", 1)[0]
            # Target container port is the last colon-separated token
            last_seg = cleaned.rsplit(":", 1)[-1]
            if last_seg.isdigit():
                result.append(int(last_seg))
    return result


def parse_compose_volume_source(vol_spec: Any) -> tuple[str | None, bool]:
    """Return `(host_source, is_bind_mount)` for a Compose volume entry."""
    if isinstance(vol_spec, dict):
        vtype = str(vol_spec.get("type", "")).lower()
        src = vol_spec.get("source")
        if src is None:
            return None, False
        src_str = str(src).strip()
        is_bind = vtype == "bind" or bool(_HOST_BIND_RE.match(src_str)) or "/" in src_str
        return src_str, is_bind

    if isinstance(vol_spec, str):
        raw = vol_spec.strip()
        # Handle Windows drive prefixes like C:\path:/container or standard src:dst[:mode]
        if len(raw) >= 3 and raw[1] == ":" and raw[2] in {"/", "\\"}:
            parts = raw.split(":", 2)
            src_str = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else raw
            return src_str, True
        if ":" not in raw:
            return None, False
        src_str = raw.split(":", 1)[0].strip()
        if not src_str:
            return None, False
        is_bind = bool(_HOST_BIND_RE.match(src_str)) or "/" in src_str or "\\" in src_str
        return src_str, is_bind

    return None, False
