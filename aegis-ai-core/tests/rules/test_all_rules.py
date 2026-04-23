"""
tests/rules/test_all_rules.py

正/负样本规则测试套件。

对 tests/rules/ 下每个 true_positive/ 和 false_positive/ 目录中的样本文件
运行对应语言的规则引擎，断言检测/不检测到目标漏洞类型。

约定：
- true_positive/  文件名以 tp_ 开头，必须被检测到对应漏洞
- false_positive/ 文件名以 fp_ 开头，不得报告任何漏洞（或不报告目标类型）

目录到漏洞类型的映射：
  nosql_injection      -> NOSQL_INJECTION
  hardcoded_credentials -> HARDCODED_CREDENTIALS
  path_traversal       -> PATH_TRAVERSAL
  xss                  -> XSS_RISK
  rce                  -> RCE_COMMAND_EXEC
  sql_injection        -> SQL_INJECTION
  deserialization      -> DESERIALIZATION
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

from src.analysis.rule_engine import (
    analyze_javascript,
    analyze_php,
    analyze_python,
    analyze_java,
    analyze_go,
)

# ------------------------------------------------------------------
# 常量
# ------------------------------------------------------------------

RULES_DIR = Path(__file__).parent

VULN_TYPE_MAP = {
    "nosql_injection": "NOSQL_INJECTION",
    "hardcoded_credentials": "HARDCODED_CREDENTIALS",
    "path_traversal": "PATH_TRAVERSAL",
    "xss": "XSS_RISK",
    "rce": "RCE_COMMAND_EXEC",
    "sql_injection": "SQL_INJECTION",
    "deserialization": "DESERIALIZATION",
    "open_redirect": "OPEN_REDIRECT",
    "ssrf": "SSRF",
}

JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx"}
PY_EXTENSIONS = {".py"}
PHP_EXTENSIONS = {".php"}
JAVA_EXTENSIONS = {".java"}
GO_EXTENSIONS = {".go"}


def _analyze(file_path: Path) -> List[dict]:
    """根据文件扩展名选择分析器并返回 findings。"""
    code = file_path.read_text(encoding="utf-8")
    ext = file_path.suffix.lower()
    if ext in JS_EXTENSIONS:
        return analyze_javascript(code, str(file_path))
    if ext in PY_EXTENSIONS:
        return analyze_python(code, str(file_path))
    if ext in PHP_EXTENSIONS:
        return analyze_php(code, str(file_path))
    if ext in JAVA_EXTENSIONS:
        return analyze_java(code, str(file_path))
    if ext in GO_EXTENSIONS:
        return analyze_go(code, str(file_path))
    return []


def _collect_cases():
    """
    遍历 tests/rules/ 下各漏洞类型目录，收集所有测试用例。

    返回列表，每项为 (file_path, vuln_type, expect_finding)。
    """
    cases = []
    for vuln_dir in RULES_DIR.iterdir():
        if not vuln_dir.is_dir() or vuln_dir.name.startswith("_"):
            continue
        vuln_type = VULN_TYPE_MAP.get(vuln_dir.name)
        if vuln_type is None:
            continue

        for label, expect in [("true_positive", True), ("false_positive", False)]:
            sub_dir = vuln_dir / label
            if not sub_dir.exists():
                continue
            for sample_file in sorted(sub_dir.iterdir()):
                if sample_file.suffix.lower() not in JS_EXTENSIONS | PY_EXTENSIONS | PHP_EXTENSIONS | JAVA_EXTENSIONS | GO_EXTENSIONS:
                    continue
                cases.append((sample_file, vuln_type, expect))
    return cases


_ALL_CASES = _collect_cases()


def _case_id(case):
    """pytest 测试用例 ID。"""
    file_path, vuln_type, expect = case
    label = "TP" if expect else "FP"
    return f"{vuln_type}::{label}::{file_path.name}"


@pytest.mark.parametrize("case", _ALL_CASES, ids=[_case_id(c) for c in _ALL_CASES])
def test_rule_sample(case):
    """
    参数化测试：对每个样本文件运行分析器，断言检测结果符合预期。

    Args:
        case: (file_path, vuln_type, expect_finding) 三元组。
    """
    file_path, vuln_type, expect_finding = case
    findings = _analyze(file_path)
    detected = any(f.get("type") == vuln_type for f in findings)

    if expect_finding:
        assert detected, (
            f"[FN] 漏洞未检出: {file_path.relative_to(RULES_DIR)}\n"
            f"期望检测到 {vuln_type}，但 findings = {findings}"
        )
    else:
        assert not detected, (
            f"[FP] 误报: {file_path.relative_to(RULES_DIR)}\n"
            f"不期望检测到 {vuln_type}，但 findings = {[f for f in findings if f.get('type') == vuln_type]}"
        )


def test_python_sqli_variable_execute_tp_case_is_included() -> None:
    """
    回归保护：tp_python_cursor_execute_format.py 不应被长期跳过。
    """
    case_names = {
        file_path.name
        for file_path, vuln_type, expect_finding in _ALL_CASES
        if vuln_type == "SQL_INJECTION" and expect_finding
    }
    assert "tp_python_cursor_execute_format.py" in case_names
