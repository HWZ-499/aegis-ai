from pathlib import Path

from scripts.check_release_consistency import validate_repo_consistency


def _write_minimal_consistent_repo(repo: Path) -> Path:
    core = repo / "aegis-ai-core"
    src_dir = core / "src"
    src_dir.mkdir(parents=True)

    (repo / "README.md").write_text(
        "# Aegis\nrequires-python >=3.10\n`pip install -e .[dev]`\ndeepseek openai ollama custom\nOLLAMA_BASE_URL=x\nDEEPSEEK_API_KEY=x\nOPENAI_API_KEY=x\n已支持 实验性 规划中\n.aegis-baseline.json 不是修复代码\n",
        encoding="utf-8",
    )
    (repo / "aegis-vscode").mkdir()
    (repo / "aegis-vscode" / "README.md").write_text(
        "# Extension\nv0.5.1\nDEEPSEEK_API_KEY=x\nOPENAI_API_KEY=x\nOLLAMA_BASE_URL=http://localhost:11434/v1\n",
        encoding="utf-8",
    )
    (repo / "docs" / "technical").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "technical" / "TECHNICAL_DESIGN_DOCUMENT.md").write_text(
        "已支持 | 实验性 | 规划中\n",
        encoding="utf-8",
    )
    (core / "pyproject.toml").write_text(
        "[project]\nrequires-python='>=3.10'\nversion='1.4.0'\n\n[project.urls]\nHomepage='https://github.com/HWZ-499/aegis-ai'\nRepository='https://github.com/HWZ-499/aegis-ai'\nIssues='https://github.com/HWZ-499/aegis-ai/issues'\n",
        encoding="utf-8",
    )
    (repo / "aegis-vscode" / "package.json").write_text(
        '{ "version": "0.5.1", "repository": { "type": "git", "url": "https://github.com/HWZ-499/aegis-ai.git" }, "bugs": { "url": "https://github.com/HWZ-499/aegis-ai/issues" }, "homepage": "https://github.com/HWZ-499/aegis-ai#readme", "contributes": { "configuration": { "properties": { "aegisAI.ai.provider": { "enum": ["deepseek", "openai", "ollama", "custom"] } } } } }',
        encoding="utf-8",
    )
    (src_dir / "README.md").write_text(
        "# Core\n\n- `analysis/` - analyzers\n- `scanner/` - scanning\n- `lsp/` - language server\n",
        encoding="utf-8",
    )
    (src_dir / "analysis").mkdir()
    (src_dir / "scanner").mkdir()
    (src_dir / "lsp").mkdir()
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
