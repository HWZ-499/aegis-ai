"""
test_php_sqli_benchmark.py - PHP SQLi 基准用例（防回归）

确保 DVWA 风格 PHP SQLi 能由生产 AST 入口检出（TP），
且参数化/安全写法不被误报（TN）。
"""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(PROJECT_ROOT))

from src.analysis.rule_engine import analyze_php

# TP：DVWA low 风格，应检出 SQL_INJECTION
PHP_TP_SQLI = """
<?php
$id = $_REQUEST['id'];
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($conn, $query);
"""


# TN：参数化查询，不应报 SQL_INJECTION
PHP_TN_PARAMETERIZED = """
<?php
$id = $_REQUEST['id'];
$stmt = $conn->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
"""


# TN：无 SQL 拼接，不应报 SQL_INJECTION
PHP_TN_NO_SQL = """
<?php
$name = $_GET['name'];
echo "Hello " . htmlspecialchars($name);
"""

PHP_TP_WEAK_ESCAPE_QUOTED = """
<?php
$user = $_POST['username'];
$user = mysqli_real_escape_string($conn, $user);
$pass = $_POST['password'];
$pass = mysqli_real_escape_string($conn, $pass);
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
mysqli_query($conn, $query);
"""

PHP_TN_STATIC_ESCAPED_VALUE = """
<?php
$user = mysqli_real_escape_string($conn, "admin");
$query = "SELECT * FROM users WHERE username='$user'";
mysqli_query($conn, $query);
"""


def _php_scan(code: str) -> list:
    """通过生产 PHP 分析入口扫描代码。"""
    return analyze_php(code, file_path="test.php", include_dsl=False)


def _has_sqli(findings: list) -> bool:
    return any(f.get("type") == "SQL_INJECTION" for f in findings)


class TestPhpSqliBenchmark:
    """PHP SQLi 基准：TP/TN 防回归。"""

    def test_php_sqli_tp_dvwa_low_style(self):
        """TP：DVWA low 风格 WHERE user_id = '$id' 应检出 SQL_INJECTION。"""
        findings = _php_scan(PHP_TP_SQLI)
        assert _has_sqli(findings), "应检出 SQL_INJECTION（DVWA low 风格）"

    def test_php_sqli_tn_parameterized(self):
        """TN：prepare + bind_param 不应报 SQL_INJECTION。"""
        findings = _php_scan(PHP_TN_PARAMETERIZED)
        assert not _has_sqli(findings), "参数化查询不应报 SQL_INJECTION"

    def test_php_sqli_tn_no_sql(self):
        """TN：无 SQL 的代码不应报 SQL_INJECTION。"""
        findings = _php_scan(PHP_TN_NO_SQL)
        assert not _has_sqli(findings), "无 SQL 代码不应报 SQL_INJECTION"

    def test_php_sqli_tp_quoted_weak_escape(self):
        findings = _php_scan(PHP_TP_WEAK_ESCAPE_QUOTED)
        assert _has_sqli(findings), "用户输入仅经数据库转义后插值到 SQL 仍应检出"

    def test_php_sqli_tn_static_escaped_value(self):
        findings = _php_scan(PHP_TN_STATIC_ESCAPED_VALUE)
        assert not _has_sqli(findings), "无用户输入来源的静态转义值不应误报"

    @pytest.mark.parametrize(
        "file_path",
        ["helpdesk.php", "app/helpers/user_lookup.php"],
    )
    def test_php_sqli_help_named_business_paths_are_scanned(self, file_path: str):
        """TP：路径里含 help 的业务 PHP 文件不能被扫描器直接跳过。"""
        findings = analyze_php(PHP_TP_SQLI, file_path=file_path, include_dsl=False)
        assert _has_sqli(findings), f"{file_path} 应检出 SQL_INJECTION"
