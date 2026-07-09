# test_ast_rules.py - 测试 AST 规则引擎
"""测试新扩展的 AST 规则引擎是否能正确检测漏洞"""

import os

import pytest

from src.analysis.rule_based_audit import audit_code_with_rules_only, merge_findings
from src.analysis.rule_engine import analyze_code_ast, scan_code_locally

# 读取测试文件
_current_dir = os.path.dirname(os.path.abspath(__file__))
_test_file_path = os.path.join(_current_dir, "test_vulnerable_code.py")
with open(_test_file_path, encoding="utf-8") as _f:
    _test_code = _f.read()


def test_ast_analysis():
    """AST 分析应检测到漏洞。"""
    ast_findings = analyze_code_ast(_test_code)
    assert len(ast_findings) > 0, "AST analysis should detect issues"
    for f in ast_findings:
        assert "line" in f, f"Finding missing 'line': {f}"
        assert "type" in f, f"Finding missing 'type': {f}"
        assert "details" in f, f"Finding missing 'details': {f}"


def test_regex_scan():
    """正则规则扫描应检测到漏洞。"""
    regex_findings = scan_code_locally(_test_code)
    assert len(regex_findings) > 0, "Regex scan should detect issues"
    for f in regex_findings:
        assert "line" in f, f"Finding missing 'line': {f}"
        assert "type" in f, f"Finding missing 'type': {f}"


def test_merge_dedup():
    """合并结果（去重后）应产生非空结果。"""
    ast_findings = analyze_code_ast(_test_code)
    regex_findings = scan_code_locally(_test_code)
    merged = merge_findings(ast_findings, regex_findings)
    assert len(merged) > 0, "Merged findings should be non-empty"


def test_severity_distribution():
    """合并结果应包含不同严重程度分类。"""
    ast_findings = analyze_code_ast(_test_code)
    regex_findings = scan_code_locally(_test_code)
    merged = merge_findings(ast_findings, regex_findings)

    critical = [f for f in merged if f.get("severity") == "Critical"]
    high = [f for f in merged if f.get("severity") == "High"]
    medium = [f for f in merged if f.get("severity") == "Medium"]
    low = [f for f in merged if f.get("severity") == "Low"]

    total = len(critical) + len(high) + len(medium) + len(low)
    assert total > 0, "Should have findings across severity levels"


def test_rule_only_audit_report():
    """纯规则审计报告应包含预期字段。"""
    result = audit_code_with_rules_only(_test_code, "test_vulnerable_code.py")
    report = result["report"]

    assert len(report) > 0, "Report should be non-empty"
    assert result["total_count"] > 0, "Should detect issues"
    assert result["rule_count"] == result["total_count"]
    assert result["ast_count"] == result["total_count"]
    assert result["regex_count"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
