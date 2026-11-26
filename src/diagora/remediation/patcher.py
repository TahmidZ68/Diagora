"""Safe patch preview and boundary-checked application interface (Phase 5 foundation)."""

from __future__ import annotations

from pathlib import Path

from diagora.core.security import validate_within_root


def verify_patch_path(target_file: str, repo_root: Path) -> Path:
    """Verify that a proposed patch target resides strictly within `repo_root`."""
    return validate_within_root(target_file, repo_root, follow_symlinks=False)
