from pathlib import Path

from scripts.check_release_consistency import validate_repo_consistency


def _write_minimal_consistent_repo(repo: Path) -> Path:
    core = repo / "aegis-ai-core"
    src_dir = core / "src"
    src_dir.mkdir(parents=True)

    (repo / "README.md").write_text(
        "# Aegis\nExtension v0.5.1\nPython 3.10-3.12; Python 3.13 unsupported\n`pip install -e .[dev]`\ndeepseek openai ollama custom\nOLLAMA_BASE_URL=x\nDEEPSEEK_API_KEY=x\nOPENAI_API_KEY=x\n.aegis-baseline.json not a fix\n",
        encoding="utf-8",
    )
    (repo / "aegis-vscode").mkdir()
    (repo / "aegis-vscode" / "README.md").write_text(
        "# Extension\nv0.5.1\n已支持 实验性 规划中\nDEEPSEEK_API_KEY=x\nOPENAI_API_KEY=x\nOLLAMA_BASE_URL=http://localhost:11434/v1\n",
        encoding="utf-8",
    )
    (repo / "docs" / "technical").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "technical" / "DETECTION_QUALITY.md").write_text(
        "Recall Precision F1\n",
        encoding="utf-8",
    )
    (repo / "docs" / "VERIFICATION_GUIDE.md").write_text(
        "python -m pytest tests/\npython -m src.scanner.cli . --format json\n",
        encoding="utf-8",
    )
    (repo / "docs" / "MAINTENANCE.md").write_text(
        "Semantic Versioning\ncore-vX.Y.Z\nvscode-vX.Y.Z\nprevious minor: 90 days\n",
        encoding="utf-8",
    )
    (repo / "docs" / "RELEASE_CHECKLIST.md").write_text(
        "pending trusted publisher\nVSCE_PAT\ncore-v1.5.0\nvscode-v0.6.7\ntwine check\n",
        encoding="utf-8",
    )
    (core / "pyproject.toml").write_text(
        "[project]\nrequires-python='>=3.10,<3.13'\nversion='1.4.0'\nreadme='README.md'\n\n[project.urls]\nHomepage='https://github.com/HWZ-499/aegis-ai'\nRepository='https://github.com/HWZ-499/aegis-ai'\nIssues='https://github.com/HWZ-499/aegis-ai/issues'\n",
        encoding="utf-8",
    )
    (core / "README.md").write_text(
        "Python 3.10 through Python 3.12\npip install aegis-ai-core\naegis /path/to/project --format json\n",
        encoding="utf-8",
    )
    (core / "CHANGELOG.md").write_text("# Changelog\n\n## 1.4.0\n", encoding="utf-8")
    (repo / "aegis-vscode" / "package.json").write_text(
        '{ "version": "0.5.1", "preview": false, "repository": { "type": "git", "url": "https://github.com/HWZ-499/aegis-ai.git" }, "bugs": { "url": "https://github.com/HWZ-499/aegis-ai/issues" }, "homepage": "https://github.com/HWZ-499/aegis-ai#readme", "contributes": { "configuration": { "properties": { "aegisAI.ai.provider": { "enum": ["deepseek", "openai", "ollama", "custom"] } } } } }',
        encoding="utf-8",
    )
    (repo / "aegis-vscode" / "CHANGELOG.md").write_text("# Changelog\n\n## 0.5.1\n", encoding="utf-8")
    (src_dir / "README.md").write_text(
        "# Core\n\n- `analysis/` - analyzers\n- `scanner/` - scanning\n- `lsp/` - language server\n",
        encoding="utf-8",
    )
    (src_dir / "analysis").mkdir()
    (src_dir / "scanner").mkdir()
    (src_dir / "lsp").mkdir()
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "publish-pypi.yml").write_text(
        "core-v*\ncheck_release_tag.py core\npypa/gh-action-pypi-publish\n",
        encoding="utf-8",
    )
    (workflows / "publish-extension.yml").write_text(
        "vscode-v*\ncheck_release_tag.py vscode\nnpm audit --omit=dev --audit-level=moderate\n"
        "xvfb-run -a npm test\ncheck_distribution.py aegis-vscode/*.vsix\nvsce publish\nsecrets.VSCE_PAT\n",
        encoding="utf-8",
    )
    return core


def test_validate_repo_consistency_accepts_current_docs(tmp_path: Path) -> None:
    """一致性检查应接受当前仓库的文档和配置口径。"""
    errors = validate_repo_consistency(Path.cwd())
    assert errors == []


def test_validate_repo_consistency_accepts_package_root_input(tmp_path: Path) -> None:
    """从 aegis-ai-core 子目录传入时也应能定位到 monorepo 根目录。"""
    repo = tmp_path / "repo"
    core = _write_minimal_consistent_repo(repo)

    errors = validate_repo_consistency(core)

    assert errors == []


def test_validate_repo_consistency_flags_missing_provider_doc(tmp_path: Path) -> None:
    """缺少 provider 文档时应明确报错。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_minimal_consistent_repo(repo)
    (repo / "README.md").write_text("# Aegis\nPython 3.10+\n`pip install -e .[dev]`\n", encoding="utf-8")

    errors = validate_repo_consistency(repo)

    assert any("AI provider" in error for error in errors)


def test_validate_repo_consistency_flags_mismatched_repository_metadata(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    (repo / "aegis-vscode" / "package.json").write_text(
        '{ "version": "0.5.1", "repository": { "type": "git", "url": "https://github.com/other-org/aegis-ai.git" }, "bugs": { "url": "https://github.com/other-org/aegis-ai/issues" }, "homepage": "https://github.com/other-org/aegis-ai#readme", "contributes": { "configuration": { "properties": { "aegisAI.ai.provider": { "enum": ["deepseek", "openai", "ollama", "custom"] } } } } }',
        encoding="utf-8",
    )

    errors = validate_repo_consistency(repo)

    assert any("repository metadata" in error.lower() for error in errors)


def test_validate_repo_consistency_flags_stale_src_directory_map(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    (repo / "aegis-ai-core" / "src" / "README.md").write_text(
        "# Core\n\n- `server/` - api server\n- `analysis/` - analyzers\n- `crawler/` - crawlers\n",
        encoding="utf-8",
    )

    errors = validate_repo_consistency(repo)

    assert any("src/readme" in error.lower() for error in errors)


def test_validate_repo_consistency_flags_stale_root_extension_version(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    (repo / "README.md").write_text(
        "# Aegis\nExtension v0.4.0\nPython 3.10-3.12; Python 3.13 unsupported\n`pip install -e .[dev]`\ndeepseek openai ollama custom\n"
        "OLLAMA_BASE_URL=x\nDEEPSEEK_API_KEY=x\nOPENAI_API_KEY=x\n.aegis-baseline.json not a fix\n",
        encoding="utf-8",
    )

    errors = validate_repo_consistency(repo)

    assert any("root readme" in error.lower() and "extension version" in error.lower() for error in errors)


def test_validate_repo_consistency_flags_undocumented_python_upper_bound(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    root_readme = repo / "README.md"
    root_readme.write_text(root_readme.read_text(encoding="utf-8").replace("; Python 3.13 unsupported", ""), encoding="utf-8")

    errors = validate_repo_consistency(repo)

    assert any("python requirement" in error.lower() for error in errors)


def test_validate_repo_consistency_flags_missing_component_changelog_version(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    (repo / "aegis-ai-core" / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")

    errors = validate_repo_consistency(repo)

    assert any("core changelog" in error.lower() for error in errors)


def test_validate_repo_consistency_flags_preview_extension(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    package_path = repo / "aegis-vscode" / "package.json"
    package = package_path.read_text(encoding="utf-8").replace('"preview": false', '"preview": true')
    package_path.write_text(package, encoding="utf-8")

    errors = validate_repo_consistency(repo)

    assert any("preview" in error.lower() for error in errors)


def test_validate_repo_consistency_flags_missing_extension_runtime_audit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_minimal_consistent_repo(repo)
    workflow_path = repo / ".github" / "workflows" / "publish-extension.yml"
    workflow = workflow_path.read_text(encoding="utf-8").replace(
        "npm audit --omit=dev --audit-level=moderate\n", ""
    )
    workflow_path.write_text(workflow, encoding="utf-8")

    errors = validate_repo_consistency(repo)

    assert any("audit runtime dependencies" in error.lower() for error in errors)
