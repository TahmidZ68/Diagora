"""Static Docker and Compose analyzer implementing rules DK001-DK010."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from diagora.analyzers.base import BaseAnalyzer
from diagora.analyzers.configuration import find_yaml_key_line, parse_yaml_safe
from diagora.analyzers.docker.parsers import (
    ParsedDockerfile,
    extract_compose_container_ports,
    parse_compose_volume_source,
    parse_dockerfile,
)
from diagora.core.classifier import DOCKER_COMPOSE_NAMES
from diagora.core.exceptions import DiagoraError, PathSecurityError
from diagora.core.models import (
    Category,
    Confidence,
    Ecosystem,
    Finding,
    RepositoryContext,
)
from diagora.core.security import safe_read_text, validate_within_root
from diagora.rules.registry import RuleRegistry
from diagora.settings import ScanSettings

_SENSITIVE_MOUNT_PREFIXES = (
    "/",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/var/run/docker.sock",
    "~/.ssh",
)
_ONESHOT_NAME_HINTS = ("migrate", "migration", "seed", "init", "setup", "bootstrap", "oneshot")


def _is_compose_file(rel_path: str) -> bool:
    return PurePosixPath(rel_path).name in DOCKER_COMPOSE_NAMES


def _is_dockerfile_path(rel_path: str) -> bool:
    name = PurePosixPath(rel_path).name
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def _join_rel_posix(base_dir: str, rel_target: str) -> str:
    cleaned = rel_target.strip().replace("\\", "/")
    if cleaned in {"", "."}:
        return base_dir if base_dir not in {"", "."} else "."
    if base_dir in {"", "."}:
        return cleaned
    return f"{base_dir.rstrip('/')}/{cleaned}"


def _is_sensitive_host_mount(source: str) -> bool:
    norm = source.strip().rstrip("/") or "/"
    if norm in {"/", "/etc", "/root", "/proc", "/sys", "/dev", "/var/run/docker.sock", "~/.ssh"}:
        return True
    return norm.startswith(("/etc/", "/root/", "/proc/", "/sys/", "/var/run/docker.sock"))


def _is_oneshot_service(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in _ONESHOT_NAME_HINTS)


class DockerAnalyzer(BaseAnalyzer):
    """Deterministic static analyzer for Dockerfiles and Compose configs (DK001-DK010)."""

    name = "docker"
    category = Category.DOCKER
    supported_ecosystems = (Ecosystem.DOCKER,)

    def analyze(
        self,
        repo_root: Path,
        context: RepositoryContext,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
    ) -> list[Finding]:
        """Inspect all discovered Dockerfiles, Compose files, and `.dockerignore` coverage."""
        findings: list[Finding] = []
        counter = 0

        def next_id() -> str:
            nonlocal counter
            counter += 1
            return f"dk-{counter:04d}"

        discovered_set = set(context.discovered_files)
        dockerfiles = sorted(f for f in context.docker_files if _is_dockerfile_path(f))
        compose_files = sorted(f for f in context.docker_files if _is_compose_file(f))

        parsed_dockerfiles: dict[str, ParsedDockerfile] = {}
        for df_path in dockerfiles:
            try:
                text = safe_read_text(
                    df_path,
                    repo_root,
                    max_bytes=settings.max_file_size_bytes,
                    follow_symlinks=settings.follow_symlinks,
                )
            except DiagoraError:
                continue
            parsed_dockerfiles[df_path] = parse_dockerfile(text, df_path)

        checked_build_dockerfiles: set[str] = set()
        compose_covered_healthcheck: set[str] = set()

        for compose_path in compose_files:
            self._analyze_compose_file(
                compose_path=compose_path,
                repo_root=repo_root,
                parsed_dockerfiles=parsed_dockerfiles,
                checked_build_dockerfiles=checked_build_dockerfiles,
                compose_covered_healthcheck=compose_covered_healthcheck,
                settings=settings,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

        # Standalone Dockerfile checks: DK006 (HEALTHCHECK) & DK010 (.dockerignore)
        has_root_dockerignore = ".dockerignore" in discovered_set
        checked_ignore_dirs: set[str] = set()

        for df_path, parsed in parsed_dockerfiles.items():
            df_dir = PurePosixPath(df_path).parent.as_posix()
            ignore_dir = "." if df_dir in {"", "."} else df_dir
            if ignore_dir not in checked_ignore_dirs:
                checked_ignore_dirs.add(ignore_dir)
                local_ignore = (
                    ".dockerignore" if ignore_dir == "." else f"{ignore_dir}/.dockerignore"
                )
                if local_ignore not in discovered_set and not has_root_dockerignore:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="DK010",
                            observed=f"No .dockerignore found for '{df_path}'",
                            expected=(
                                "A `.dockerignore` file in the build context or repository root"
                            ),
                            details={"dockerfile": df_path, "context_dir": ignore_dir},
                            file=df_path,
                            line=1,
                            confidence=Confidence.HIGH,
                        )
                    )

            if (
                df_path not in checked_build_dockerfiles
                and df_path not in compose_covered_healthcheck
                and not parsed.has_healthcheck
                and not _is_oneshot_service(PurePosixPath(df_path).stem)
            ):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK006",
                        observed=f"Dockerfile '{df_path}' has no HEALTHCHECK instruction",
                        expected="HEALTHCHECK instruction in Dockerfile or healthcheck in Compose",
                        details={"dockerfile": df_path},
                        file=df_path,
                        line=1,
                        confidence=Confidence.MEDIUM,
                    )
                )

        return findings

    def _analyze_compose_file(
        self,
        *,
        compose_path: str,
        repo_root: Path,
        parsed_dockerfiles: dict[str, ParsedDockerfile],
        checked_build_dockerfiles: set[str],
        compose_covered_healthcheck: set[str],
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        try:
            text = safe_read_text(
                compose_path,
                repo_root,
                max_bytes=settings.max_file_size_bytes,
                follow_symlinks=settings.follow_symlinks,
            )
        except DiagoraError:
            return

        data, yaml_err, yaml_line = parse_yaml_safe(text)
        if yaml_err is not None or not isinstance(data, dict):
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK003",
                    observed=yaml_err or "Compose file root must be a YAML mapping",
                    expected="Valid YAML Compose specification",
                    details={"error": yaml_err or "invalid_root"},
                    file=compose_path,
                    line=yaml_line or 1,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return

        services = data.get("services")
        if not isinstance(services, dict) or not services:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK003",
                    observed="Compose file is missing a valid non-empty `services` mapping",
                    expected="Top-level `services:` mapping defining container services",
                    details={"keys": sorted(str(k) for k in data)},
                    file=compose_path,
                    line=find_yaml_key_line(text, "services") or 1,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return

        defined_services = {str(name) for name in services}
        compose_dir = PurePosixPath(compose_path).parent.as_posix()

        for svc_key, svc_cfg in services.items():
            svc_name = str(svc_key)
            svc_line = find_yaml_key_line(text, svc_name) or 1
            if not isinstance(svc_cfg, dict):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK003",
                        observed=f"Service '{svc_name}' configuration must be a mapping",
                        expected="YAML mapping of service options",
                        details={"service": svc_name},
                        file=compose_path,
                        line=svc_line,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                continue

            linked_df_rel = self._check_build_and_dockerfile(
                svc_name=svc_name,
                svc_cfg=svc_cfg,
                svc_line=svc_line,
                compose_path=compose_path,
                compose_dir=compose_dir,
                text=text,
                repo_root=repo_root,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

            self._check_env_files(
                svc_name=svc_name,
                svc_cfg=svc_cfg,
                svc_line=svc_line,
                compose_path=compose_path,
                compose_dir=compose_dir,
                text=text,
                repo_root=repo_root,
                settings=settings,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

            self._check_service_refs(
                svc_name=svc_name,
                svc_cfg=svc_cfg,
                svc_line=svc_line,
                compose_path=compose_path,
                text=text,
                defined_services=defined_services,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

            self._check_privileged_and_volumes(
                svc_name=svc_name,
                svc_cfg=svc_cfg,
                svc_line=svc_line,
                compose_path=compose_path,
                compose_dir=compose_dir,
                text=text,
                repo_root=repo_root,
                settings=settings,
                rule_registry=rule_registry,
                findings=findings,
                next_id=next_id,
            )

            # DK005 & DK006 involving build Dockerfile + Compose service
            parsed_df = parsed_dockerfiles.get(linked_df_rel) if linked_df_rel else None
            if linked_df_rel and parsed_df is not None:
                checked_build_dockerfiles.add(linked_df_rel)
                if parsed_df.exposed_ports and svc_cfg.get("ports"):
                    compose_ports = extract_compose_container_ports(svc_cfg.get("ports"))
                    exposed_nums = {p for p, _ in parsed_df.exposed_ports}
                    if compose_ports and not (set(compose_ports) & exposed_nums):
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="DK005",
                                observed=(
                                    f"Service '{svc_name}' maps container port(s) "
                                    f"{sorted(set(compose_ports))} while '{linked_df_rel}' "
                                    f"exposes {sorted(exposed_nums)}"
                                ),
                                expected=f"Container port matching EXPOSE {sorted(exposed_nums)}",
                                details={
                                    "service": svc_name,
                                    "compose_container_ports": sorted(set(compose_ports)),
                                    "dockerfile_exposed_ports": sorted(exposed_nums),
                                },
                                file=compose_path,
                                line=find_yaml_key_line(text, "ports", svc_line) or svc_line,
                                confidence=Confidence.HIGH,
                            )
                        )

            has_compose_hc = isinstance(svc_cfg.get("healthcheck"), dict)
            if has_compose_hc and linked_df_rel:
                compose_covered_healthcheck.add(linked_df_rel)

            has_df_hc = parsed_df.has_healthcheck if parsed_df is not None else False
            if (
                not has_compose_hc
                and not has_df_hc
                and not _is_oneshot_service(svc_name)
                and (linked_df_rel is not None or svc_cfg.get("ports") or svc_cfg.get("image"))
            ):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK006",
                        observed=(
                            f"Service '{svc_name}' lacks a Compose `healthcheck` "
                            "or Dockerfile `HEALTHCHECK`"
                        ),
                        expected=f"Health check configuration for service '{svc_name}'",
                        details={"service": svc_name, "dockerfile": linked_df_rel},
                        file=compose_path,
                        line=svc_line,
                        confidence=Confidence.MEDIUM,
                    )
                )

    def _check_build_and_dockerfile(
        self,
        *,
        svc_name: str,
        svc_cfg: dict[str, Any],
        svc_line: int,
        compose_path: str,
        compose_dir: str,
        text: str,
        repo_root: Path,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> str | None:
        build = svc_cfg.get("build")
        if build is None:
            return None

        if isinstance(build, str):
            ctx_raw = build
            df_raw = "Dockerfile"
        elif isinstance(build, dict):
            ctx_raw = str(build.get("context", "."))
            df_raw = str(build.get("dockerfile", "Dockerfile"))
        else:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK003",
                    observed=f"Service '{svc_name}' has invalid `build` specification type",
                    expected="String path or mapping with `context` / `dockerfile`",
                    details={"service": svc_name},
                    file=compose_path,
                    line=find_yaml_key_line(text, "build", svc_line) or svc_line,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        if "${" in ctx_raw:
            return None

        ctx_rel = _join_rel_posix(compose_dir, ctx_raw)
        try:
            resolved_ctx = validate_within_root(ctx_rel, repo_root)
        except PathSecurityError:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK002",
                    observed=f"Build context '{ctx_raw}' escapes the repository boundary",
                    expected="Build context directory within repository root",
                    details={"service": svc_name, "context": ctx_raw},
                    file=compose_path,
                    line=find_yaml_key_line(text, "build", svc_line) or svc_line,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        if not resolved_ctx.is_dir():
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK002",
                    observed=f"Build context directory '{ctx_raw}' does not exist",
                    expected="Existing build context directory",
                    details={"service": svc_name, "context": ctx_raw},
                    file=compose_path,
                    line=find_yaml_key_line(text, "build", svc_line) or svc_line,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        if "${" in df_raw:
            return None

        df_rel_in_ctx = _join_rel_posix(
            resolved_ctx.relative_to(repo_root).as_posix(),
            df_raw,
        )
        try:
            resolved_df = validate_within_root(df_rel_in_ctx, repo_root)
        except PathSecurityError:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK001",
                    observed=f"Dockerfile path '{df_raw}' escapes repository boundary",
                    expected="Dockerfile inside repository root",
                    details={"service": svc_name, "dockerfile": df_raw},
                    file=compose_path,
                    line=find_yaml_key_line(text, "dockerfile", svc_line) or svc_line,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        if not resolved_df.is_file():
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK001",
                    observed=df_rel_in_ctx.lstrip("./"),
                    expected=f"Existing Dockerfile at '{df_rel_in_ctx.lstrip('./')}'",
                    details={"service": svc_name, "context": ctx_raw, "dockerfile": df_raw},
                    file=compose_path,
                    line=find_yaml_key_line(text, "dockerfile", svc_line)
                    or find_yaml_key_line(text, "build", svc_line)
                    or svc_line,
                    confidence=Confidence.CONFIRMED,
                )
            )
            return None

        return resolved_df.relative_to(repo_root).as_posix()

    def _check_env_files(
        self,
        *,
        svc_name: str,
        svc_cfg: dict[str, Any],
        svc_line: int,
        compose_path: str,
        compose_dir: str,
        text: str,
        repo_root: Path,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        env_file = svc_cfg.get("env_file")
        if env_file is None:
            return
        items = env_file if isinstance(env_file, list) else [env_file]
        env_line = find_yaml_key_line(text, "env_file", svc_line) or svc_line

        for item in items:
            if isinstance(item, dict):
                if item.get("required") is False:
                    continue
                path_val = str(item.get("path", "")).strip()
            else:
                path_val = str(item).strip()
            if not path_val or "${" in path_val:
                continue

            target_rel = _join_rel_posix(compose_dir, path_val)
            try:
                resolved = validate_within_root(
                    target_rel,
                    repo_root,
                    follow_symlinks=settings.follow_symlinks,
                )
                exists = resolved.is_file()
            except PathSecurityError:
                exists = False

            if not exists:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK004",
                        observed=f"Service '{svc_name}' references missing env_file '{path_val}'",
                        expected=f"Existing env_file at '{path_val}' (or set `required: false`)",
                        details={"service": svc_name, "env_file": path_val},
                        file=compose_path,
                        line=env_line,
                        confidence=Confidence.HIGH,
                    )
                )

    def _check_service_refs(
        self,
        *,
        svc_name: str,
        svc_cfg: dict[str, Any],
        svc_line: int,
        compose_path: str,
        text: str,
        defined_services: set[str],
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        dep_targets: list[tuple[str, str]] = []
        depends_on = svc_cfg.get("depends_on")
        if isinstance(depends_on, (list, dict)):
            for item in depends_on:
                dep_targets.append(("depends_on", str(item).strip()))

        links = svc_cfg.get("links")
        if isinstance(links, list):
            for item in links:
                dep_targets.append(("links", str(item).split(":", 1)[0].strip()))

        net_mode = svc_cfg.get("network_mode")
        if isinstance(net_mode, str) and net_mode.startswith("service:"):
            dep_targets.append(("network_mode", net_mode.split(":", 1)[1].strip()))

        for field_name, target in dep_targets:
            if target and target not in defined_services:
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK007",
                        observed=(
                            f"Service '{svc_name}' `{field_name}` references undefined "
                            f"service '{target}'"
                        ),
                        expected=f"Service '{target}' defined under `services:`",
                        details={
                            "service": svc_name,
                            "field": field_name,
                            "referenced_service": target,
                        },
                        file=compose_path,
                        line=find_yaml_key_line(text, field_name, svc_line) or svc_line,
                        confidence=Confidence.CONFIRMED,
                    )
                )

    def _check_privileged_and_volumes(
        self,
        *,
        svc_name: str,
        svc_cfg: dict[str, Any],
        svc_line: int,
        compose_path: str,
        compose_dir: str,
        text: str,
        repo_root: Path,
        settings: ScanSettings,
        rule_registry: RuleRegistry,
        findings: list[Finding],
        next_id: Any,
    ) -> None:
        if svc_cfg.get("privileged") is True:
            findings.append(
                rule_registry.create_finding(
                    finding_id=next_id(),
                    rule_id="DK008",
                    observed=f"Service '{svc_name}' runs with `privileged: true`",
                    expected="Unprivileged container or minimal explicit `cap_add`",
                    details={"service": svc_name, "setting": "privileged: true"},
                    file=compose_path,
                    line=find_yaml_key_line(text, "privileged", svc_line) or svc_line,
                    confidence=Confidence.CONFIRMED,
                )
            )
        for ns_key in ("network_mode", "pid", "ipc"):
            if str(svc_cfg.get(ns_key, "")).strip().lower() == "host":
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK008",
                        observed=f"Service '{svc_name}' shares host namespace via `{ns_key}: host`",
                        expected=f"Isolated container namespace instead of `{ns_key}: host`",
                        details={"service": svc_name, "setting": f"{ns_key}: host"},
                        file=compose_path,
                        line=find_yaml_key_line(text, ns_key, svc_line) or svc_line,
                        confidence=Confidence.HIGH,
                    )
                )

        volumes = svc_cfg.get("volumes")
        if not isinstance(volumes, list):
            return
        vol_line = find_yaml_key_line(text, "volumes", svc_line) or svc_line
        for vol in volumes:
            source, is_bind = parse_compose_volume_source(vol)
            if not source or not is_bind or "${" in source:
                continue
            if _is_sensitive_host_mount(source):
                findings.append(
                    rule_registry.create_finding(
                        finding_id=next_id(),
                        rule_id="DK009",
                        observed=f"Service '{svc_name}' mounts sensitive host path '{source}'",
                        expected="Project-scoped bind mount or named Docker volume",
                        details={"service": svc_name, "volume_source": source},
                        file=compose_path,
                        line=vol_line,
                        confidence=Confidence.CONFIRMED,
                    )
                )
                continue

            if not source.startswith(("/", "~")):
                target_rel = _join_rel_posix(compose_dir, source)
                try:
                    resolved = validate_within_root(
                        target_rel,
                        repo_root,
                        follow_symlinks=settings.follow_symlinks,
                    )
                    if not resolved.exists():
                        findings.append(
                            rule_registry.create_finding(
                                finding_id=next_id(),
                                rule_id="DK009",
                                observed=(
                                    f"Service '{svc_name}' bind-mounts missing path '{source}'"
                                ),
                                expected=f"Existing repository path for bind mount '{source}'",
                                details={"service": svc_name, "volume_source": source},
                                file=compose_path,
                                line=vol_line,
                                confidence=Confidence.MEDIUM,
                            )
                        )
                except PathSecurityError:
                    findings.append(
                        rule_registry.create_finding(
                            finding_id=next_id(),
                            rule_id="DK009",
                            observed=(
                                f"Service '{svc_name}' bind mount '{source}' "
                                "escapes repository root"
                            ),
                            expected="Bind mount contained inside the repository",
                            details={"service": svc_name, "volume_source": source},
                            file=compose_path,
                            line=vol_line,
                            confidence=Confidence.CONFIRMED,
                        )
                    )
