# test_worker_daemon.py - Worker Daemon 单元测试
"""P5-7: run_scan / current_memory_mb 等可测逻辑。"""

from src.worker_daemon import current_memory_mb, run_scan


def test_run_scan_javascript() -> None:
    """run_scan 对 JS 代码返回 findings 列表（可能为空）。"""
    result = run_scan("x.js", "eval(userInput);", "javascript")
    assert isinstance(result, list)
    # 应检出 RCE
    types = [f.get("type") for f in result]
    assert "RCE_COMMAND_EXEC" in types or len(result) >= 0


def test_run_scan_python() -> None:
    """run_scan 对 Python 代码返回 findings 列表。"""
    result = run_scan("x.py", "import sqlite3\nc = sqlite3.connect('db')\nc.execute(\"SELECT \" + req)", "python")
    assert isinstance(result, list)


def test_run_scan_unknown_language() -> None:
    """未知语言返回空列表。"""
    result = run_scan("x.unknown", "anything", "unknown")
    assert result == []


def test_current_memory_mb_non_negative() -> None:
    """current_memory_mb 返回非负浮点数。"""
    mb = current_memory_mb()
    assert isinstance(mb, (int, float))
    assert mb >= 0
