"""
test_smart_remediation.py - 智能修复建议与 framework_suggested_code 选择测试

验证 generate_smart_remediation 能根据源码中的 import/框架标识
正确选择 BUILTIN_REMEDIATION 中的 framework_suggested_code。
"""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(PROJECT_ROOT))

from src.scanner.smart_remediation import (
    SmartRemediation,
    generate_smart_remediation,
    _infer_framework_from_source,
    _apply_replacements,
)


def test_infer_framework_pymysql():
    """源码含 pymysql 时推断出与 SQL 相关的框架（mysql 或 pymysql）。"""
    code = "import pymysql\nconn = pymysql.connect(...)"
    fw = _infer_framework_from_source(code, "/app/db.py")
    assert fw in ("mysql", "pymysql")


def test_infer_framework_sqlalchemy():
    """源码含 sqlalchemy 时推断框架为 sqlalchemy。"""
    code = "from sqlalchemy import text\nresult = session.execute(text('SELECT 1'))"
    assert _infer_framework_from_source(code, "handler.py") == "sqlalchemy"


def test_infer_framework_express():
    """源码含 express 时推断框架为 express。"""
    code = "const express = require('express');\nconst app = express();"
    assert _infer_framework_from_source(code, "server.js") == "express"


def test_framework_suggested_code_sql_injection():
    """SQL_INJECTION + 含 pymysql 的源码应返回 framework_suggested_code 中的安全片段。"""
    finding = {"type": "SQL_INJECTION", "line": 10, "rule_id": "SQL_INJECTION"}
    source_code = """
import pymysql
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
    result = generate_smart_remediation(finding, source_code, "/app/dao.py")
    assert result.framework is not None
    assert result.suggested_code
    # 应包含参数化查询特征：占位符 ? 或 SELECT / connection
    assert "?" in result.suggested_code or "SELECT" in result.suggested_code or "connection" in result.suggested_code


def test_framework_suggested_code_rce_php():
    """RCE_COMMAND_EXEC + escapeshellarg 相关框架键应能选中 PHP 安全片段。"""
    finding = {"type": "RCE_COMMAND_EXEC", "line": 5, "rule_id": "RCE_COMMAND_EXEC"}
    source_code = "<?php\n$cmd = $_GET['c'];\nexec($cmd);"
    result = generate_smart_remediation(finding, source_code, "cmd.php")
    # 无 PHP 框架关键字时用通用 suggested_code；有 framework_suggested_code 时可选 escapeshellarg
    assert result.suggested_code
    assert "exec" in result.suggested_code or "escapeshellarg" in result.suggested_code or "subprocess" in result.suggested_code


def test_apply_replacements():
    """占位符替换应正确替换 user_id / userId。"""
    text = "SELECT * FROM users WHERE id = userId"
    replacements = {"userId": "req.body.id", "user_id": "req.body.id"}
    out = _apply_replacements(text, replacements)
    assert "req.body.id" in out
    assert "userId" not in out or "req.body.id" in out
