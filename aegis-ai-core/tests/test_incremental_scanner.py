# test_incremental_scanner.py - 增量扫描器测试
"""P5-7: IncrementalScanner get_changed_files / get_changed_lines / 非 Git 场景。"""

from pathlib import Path

import pytest

from src.scanner.incremental_scanner import IncrementalScanner


def test_incremental_scanner_invalid_path() -> None:
    """项目路径不存在时抛出 ValueError。"""
    with pytest.raises(ValueError, match="项目路径不存在"):
        IncrementalScanner(str(Path("/nonexistent/path/xyz")))


def test_incremental_scanner_not_git_repo(tmp_path: Path) -> None:
    """非 Git 仓库时 get_changed_files 返回空集合。"""
    (tmp_path / "foo.js").write_text("console.log(1);")
    scanner = IncrementalScanner(str(tmp_path))
    changed = scanner.get_changed_files()
    assert changed == set()


def test_incremental_scanner_get_changed_lines_not_git(tmp_path: Path) -> None:
    """非 Git 仓库时 get_changed_lines 返回空集合。"""
    (tmp_path / "a.py").write_text("x = 1\n")
    scanner = IncrementalScanner(str(tmp_path))
    lines = scanner.get_changed_lines(tmp_path / "a.py")
    assert lines == set()


def test_incremental_scanner_scan_incremental_no_changes(tmp_path: Path) -> None:
    """无变更时 scan_incremental 返回空字典。"""
    (tmp_path / "b.js").write_text("const x = 1;")
    scanner = IncrementalScanner(str(tmp_path))
    results = scanner.scan_incremental(verbose=False)
    assert results == {}
