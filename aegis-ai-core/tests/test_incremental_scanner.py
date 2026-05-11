# test_incremental_scanner.py - 增量扫描器测试
"""P5-7: IncrementalScanner get_changed_files / get_changed_lines / 非 Git 场景。"""

import shutil
import subprocess
from pathlib import Path

import pytest

from src.scanner.incremental_scanner import IncrementalScanner


def _require_git() -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not available")


def _run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _init_git_repo(repo: Path) -> None:
    _require_git()
    _run_git(repo, "init")
    _run_git(repo, "config", "user.email", "aegis-test@example.com")
    _run_git(repo, "config", "user.name", "Aegis Test")
    (repo / "existing.js").write_text("const safe = 1;\n", encoding="utf-8")
    _run_git(repo, "add", "existing.js")
    _run_git(repo, "commit", "-m", "initial")


def test_incremental_scanner_invalid_path() -> None:
    """项目路径不存在时抛出 ValueError。"""
    with pytest.raises(ValueError, match="项目路径不存在"):
        IncrementalScanner(str(Path("/nonexistent/path/xyz")))


def test_incremental_scanner_not_git_repo(tmp_path: Path) -> None:
    """非 Git 仓库时回退为扫描发现到的所有源码文件。"""
    (tmp_path / "foo.js").write_text("console.log(1);")
    scanner = IncrementalScanner(str(tmp_path))
    changed = scanner.get_changed_files()
    assert changed == {(tmp_path / "foo.js").resolve()}


def test_incremental_scanner_get_changed_lines_not_git(tmp_path: Path) -> None:
    """非 Git 仓库时 get_changed_lines 返回空集合。"""
    (tmp_path / "a.py").write_text("x = 1\n")
    scanner = IncrementalScanner(str(tmp_path))
    lines = scanner.get_changed_lines(tmp_path / "a.py")
    assert lines == set()


def test_incremental_scanner_scan_incremental_no_changes(tmp_path: Path) -> None:
    """Git 仓库无变更时 scan_incremental 返回空字典。"""
    (tmp_path / "b.js").write_text("const x = 1;")
    _init_git_repo(tmp_path)
    _run_git(tmp_path, "add", "b.js")
    _run_git(tmp_path, "commit", "-m", "add b")
    scanner = IncrementalScanner(str(tmp_path))
    results = scanner.scan_incremental(verbose=False)
    assert results == {}


def test_incremental_scanner_git_includes_untracked_source_files(tmp_path: Path) -> None:
    """Git 增量扫描必须包含未跟踪源码文件，避免新建漏洞文件漏扫。"""
    _init_git_repo(tmp_path)
    untracked = tmp_path / "new_vuln.js"
    untracked.write_text("eval(req.body.code);\n", encoding="utf-8")

    scanner = IncrementalScanner(str(tmp_path))
    changed = scanner.get_changed_files()

    assert untracked.resolve() in changed


def test_incremental_scan_non_git_falls_back_to_full_source_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """非 Git 的 --incremental 不应假干净，应按发现到的源码文件执行扫描。"""
    app = tmp_path / "app.js"
    app.write_text("eval(req.body.code);\n", encoding="utf-8")
    scanner = IncrementalScanner(str(tmp_path))

    monkeypatch.setattr(
        scanner.scanner,
        "scan_file",
        lambda file_path: [{"type": "RCE_COMMAND_EXEC", "line": 1}] if file_path == app.resolve() else [],
    )

    results = scanner.scan_incremental(verbose=False)

    assert results == {"app.js": [{"type": "RCE_COMMAND_EXEC", "line": 1}]}


def test_incremental_scan_stats_report_partial_scan_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """增量扫描的 stats 也必须暴露扫描错误，避免 CLI incremental 假干净。"""
    app = tmp_path / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")

    def fail_analyzer(*args, **kwargs):
        raise RuntimeError("parser unavailable")

    monkeypatch.setattr("src.scanner.project_scanner.analyze_python_new", fail_analyzer)

    scanner = IncrementalScanner(str(tmp_path))
    results, stats = scanner.scan_with_stats(verbose=False)

    assert results == {}
    assert stats["partial"] is True
    assert stats["error_count"] == 1
    assert stats["errors"] == [
        {
            "file": "app.py",
            "phase": "scan",
            "message": "parser unavailable",
        }
    ]
