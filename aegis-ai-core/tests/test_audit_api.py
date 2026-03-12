# test_audit_api.py - 直接测试审计函数
"""直接测试审计函数，不通过 HTTP，定位错误"""

import os

import pytest

from src.analysis.rule_based_audit import audit_code_with_rules_only, merge_findings
from src.analysis.rule_engine import analyze_code_ast, scan_code_locally

# 读取测试文件
_current_dir = os.path.dirname(os.path.abspath(__file__))
_test_file_path = os.path.join(_current_dir, "test_vulnerable_code.py")
with open(_test_file_path, encoding="utf-8") as _f:
    _test_code = _f.read()


def test_dual_detection():
    """双重检测: AST + Regex + Merge all produce results."""
    ast_findings = analyze_code_ast(_test_code)
    regex_findings = scan_code_locally(_test_code)
    merged_findings = merge_findings(ast_findings, regex_findings)

    assert len(ast_findings) > 0, "AST analysis should find issues"
    assert len(regex_findings) > 0, "Regex analysis should find issues"
    assert len(merged_findings) > 0, "Merged findings should be non-empty"


def test_rule_only_audit():
    """纯规则审计 should produce a report with findings."""
    result = audit_code_with_rules_only(_test_code, "test_vulnerable_code.py")

    assert len(result["report"]) > 0, "Report should be non-empty"
    assert result["total_count"] > 0, "Should detect at least one issue"


def test_severity_stats():
    """严重程度统计 should cover known severity levels."""
    ast_findings = analyze_code_ast(_test_code)
    regex_findings = scan_code_locally(_test_code)
    merged_findings = merge_findings(ast_findings, regex_findings)

    severity_count = {
        "Critical": len([f for f in merged_findings if f.get("severity") == "Critical"]),
        "High": len([f for f in merged_findings if f.get("severity") == "High"]),
        "Medium": len([f for f in merged_findings if f.get("severity") == "Medium"]),
        "Low": len([f for f in merged_findings if f.get("severity") == "Low"]),
    }

    total = sum(severity_count.values())
    assert total > 0, f"Expected findings across severities, got {severity_count}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
