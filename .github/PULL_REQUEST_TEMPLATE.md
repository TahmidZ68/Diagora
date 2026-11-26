## Summary

<!-- Describe what this PR changes and why. -->

## Type of Change

- [ ] Bug fix
- [ ] New diagnostic rule or analyzer enhancement
- [ ] Security hardening
- [ ] Documentation update
- [ ] CI / packaging / tests

## Checklist

- [ ] Static analyzers remain strictly read-only and never execute repository scripts or network calls
- [ ] File access uses `diagora.core.security` helpers (boundary, symlink, and size checks)
- [ ] Added or updated unit, integration, golden, or security tests
- [ ] Ran `ruff check src tests`
- [ ] Ran `mypy src`
- [ ] Ran `pytest -v`
- [ ] Updated documentation / `CHANGELOG.md` if user-facing behavior changed
