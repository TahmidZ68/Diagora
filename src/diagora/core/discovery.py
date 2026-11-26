"""Repository discovery interface and safe filesystem traversal engine."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from diagora.core.exceptions import PathSecurityError, RepositoryPermissionError
from diagora.core.security import validate_repository_root, validate_within_root
from diagora.settings import ScanSettings


@dataclass(slots=True)
class DiscoveryResult:
    """Raw file inventory produced by scanning a repository directory tree."""

    repo_root: Path
    repository_name: str
    is_git_repository: bool
    files: list[str] = field(default_factory=list)
    skipped_symlinks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated_by_limit: bool = False


class RepositoryDiscoverer(Protocol):
    """Protocol for repository file discovery implementations."""

    def discover(self, repo_root: Path, settings: ScanSettings) -> DiscoveryResult:
        """Traverse `repo_root` safely and return a `DiscoveryResult`."""


class FileSystemRepositoryDiscoverer:
    """Deterministic, boundary-enforcing filesystem repository discoverer."""

    def discover(self, repo_root: Path, settings: ScanSettings) -> DiscoveryResult:
        """Discover files inside `repo_root` while enforcing symlink and depth boundaries."""
        resolved_root = validate_repository_root(repo_root)
        repo_name = resolved_root.name or "repository"

        git_marker = resolved_root / ".git"
        is_git = False
        try:
            if not git_marker.is_symlink() and git_marker.exists():
                is_git = True
        except OSError:
            is_git = False

        discovered_files: list[str] = []
        skipped_symlinks: list[str] = []
        warnings: list[str] = []
        truncated = False

        def _walk(current_dir: Path, depth: int) -> None:
            nonlocal truncated
            if truncated:
                return
            if depth > settings.max_scan_depth:
                rel_dir = current_dir.relative_to(resolved_root).as_posix()
                warnings.append(
                    f"Maximum scan depth ({settings.max_scan_depth}) reached at '{rel_dir}'."
                )
                return

            try:
                with os.scandir(current_dir) as scanner:
                    entries = sorted(scanner, key=lambda e: e.name)
            except PermissionError as exc:
                if current_dir == resolved_root:
                    raise RepositoryPermissionError(
                        f"Permission denied reading repository root: {resolved_root}"
                    ) from exc
                rel_dir = current_dir.relative_to(resolved_root).as_posix()
                warnings.append(f"Permission denied scanning directory '{rel_dir}'.")
                return
            except OSError as exc:
                rel_dir = current_dir.relative_to(resolved_root).as_posix()
                warnings.append(f"Unable to read directory '{rel_dir}': {exc}")
                return

            for entry in entries:
                if len(discovered_files) >= settings.max_files_scanned:
                    truncated = True
                    warnings.append(
                        f"Maximum file scan limit ({settings.max_files_scanned}) "
                        "reached; truncating discovery."
                    )
                    return

                entry_path = current_dir / entry.name
                rel_posix = entry_path.relative_to(resolved_root).as_posix()

                try:
                    is_link = entry.is_symlink()
                except OSError:
                    continue

                if is_link:
                    if not settings.follow_symlinks:
                        skipped_symlinks.append(rel_posix)
                        warnings.append(f"Skipped symbolic link '{rel_posix}'.")
                        continue
                    try:
                        validate_within_root(
                            entry_path,
                            resolved_root,
                            follow_symlinks=True,
                        )
                    except PathSecurityError:
                        skipped_symlinks.append(rel_posix)
                        warnings.append(
                            f"Blocked symbolic link escaping repository boundary: '{rel_posix}'."
                        )
                        continue

                try:
                    is_dir = entry.is_dir(follow_symlinks=settings.follow_symlinks)
                    is_file = entry.is_file(follow_symlinks=settings.follow_symlinks)
                except OSError:
                    continue

                if is_dir:
                    if entry.name in settings.ignored_directories:
                        continue
                    _walk(entry_path, depth + 1)
                elif is_file:
                    discovered_files.append(rel_posix)

        _walk(resolved_root, depth=1)

        return DiscoveryResult(
            repo_root=resolved_root,
            repository_name=repo_name,
            is_git_repository=is_git,
            files=sorted(discovered_files),
            skipped_symlinks=sorted(skipped_symlinks),
            warnings=warnings,
            truncated_by_limit=truncated,
        )
