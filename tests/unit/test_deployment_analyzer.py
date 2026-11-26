"""Unit tests for DeploymentAnalyzer (DP001-DP003)."""

from __future__ import annotations

from pathlib import Path

from diagora.core.orchestrator import ScanOrchestrator


def test_valid_ci_workflow_and_matrix_passes_without_false_positives(tmp_path: Path) -> None:
    repo = tmp_path / "valid-deploy"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="0.1.0"\nrequires-python=">=3.10"\n',
        encoding="utf-8",
    )
    (repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    scripts = repo / "scripts"
    scripts.mkdir()
    (scripts / "verify.py").write_text("print('ok')\n", encoding="utf-8")

    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    strategy:\n"
        "      matrix:\n"
        "        python-version: ['3.10', '3.11', '3.12']\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "        with:\n"
        "          python-version: ${{ matrix.python-version }}\n"
        "      - run: python scripts/verify.py\n",
        encoding="utf-8",
    )

    res = ScanOrchestrator().scan(repo)
    assert "deployment" in res.summary.analyzers_executed
    dp_findings = [f for f in res.findings if f.category.value == "deployment"]
    assert dp_findings == []


def test_dp001_dp002_and_dp003_across_workflow_and_vercel(tmp_path: Path) -> None:
    repo = tmp_path / "broken-deploy"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="0.1.0"\nrequires-python=">=3.12"\n',
        encoding="utf-8",
    )
    (repo / "package.json").write_text(
        '{"name": "web", "engines": {"node": ">=20"}}\n',
        encoding="utf-8",
    )
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "deploy.yml").write_text(
        "name: Deploy\n"
        "on: [push]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "        with:\n"
        "          python-version: '3.9'\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          node-version: '16'\n"
        "      - run: bash ./scripts/missing-deploy.sh\n",
        encoding="utf-8",
    )
    (wf_dir / "broken.yml").write_text("name: Broken\non: [push\n", encoding="utf-8")
    (repo / "vercel.json").write_text(
        '{"builds": [{"src": "api/missing.py", "use": "@vercel/python"}], '
        '"engines": {"node": "18.x"}}\n',
        encoding="utf-8",
    )

    res = ScanOrchestrator().scan(repo)
    dp_findings = [f for f in res.findings if f.category.value == "deployment"]
    dp_rules = {f.rule_id for f in dp_findings}
    assert dp_rules == {"DP001", "DP002", "DP003"}
    assert len([f for f in dp_findings if f.rule_id == "DP003"]) >= 3
