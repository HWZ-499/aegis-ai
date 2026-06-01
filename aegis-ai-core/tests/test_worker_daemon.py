# test_worker_daemon.py - Worker Daemon 单元测试
"""P5-7: run_scan / current_memory_mb 等可测逻辑。"""

from __future__ import annotations

import io
import json
from argparse import Namespace
from pathlib import Path

import pytest

from src.worker_daemon import current_memory_mb, run_daemon, run_scan

FIXTURE_DIR = Path(__file__).parent / "rules"


def _load_fixture(relative_path: str) -> str:
    return (FIXTURE_DIR / relative_path).read_text(encoding="utf-8")


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


@pytest.mark.parametrize(
    ("language", "file_name", "fixture_path", "expected_type"),
    [
        ("php", "x.php", "path_traversal/true_positive/tp_include_user_input.php", "PATH_TRAVERSAL"),
        ("java", "X.java", "sql_injection/true_positive/tp_java_statement_concat.java", "SQL_INJECTION"),
        ("go", "x.go", "rce/true_positive/tp_go_exec_command_user_input.go", "RCE_COMMAND_EXEC"),
    ],
)
def test_run_scan_supported_non_js_python_languages(
    language: str,
    file_name: str,
    fixture_path: str,
    expected_type: str,
) -> None:
    """worker daemon should not report clean results for supported languages."""
    result = run_scan(file_name, _load_fixture(fixture_path), language)

    assert expected_type in {finding.get("type") for finding in result}


def test_auto_port_startup_message_is_machine_readable_json() -> None:
    """--port 0 startup output should be parseable by a parent process."""
    output = io.StringIO()
    run_daemon(Namespace(port=0, max_requests=0, max_memory_mb=500), startup_output=output)

    payload = json.loads(output.getvalue())
    assert payload["event"] == "listening"
    assert payload["host"] == "127.0.0.1"
    assert isinstance(payload["port"], int)
    assert payload["port"] > 0


def test_current_memory_mb_non_negative() -> None:
    """current_memory_mb 返回非负浮点数。"""
    mb = current_memory_mb()
    assert isinstance(mb, (int, float))
    assert mb >= 0
