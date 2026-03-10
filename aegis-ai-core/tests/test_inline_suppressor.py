"""
test_inline_suppressor.py - InlineSuppressor 单元测试

测试 false_positive_manager.InlineSuppressor 的内联注释抑制逻辑：
- 行末 # aegis-ignore 通配符
- 行末 # aegis-ignore: VULN_TYPE 类型特定
- 行上方注释（前缀注释）
- // 风格注释（JS/TS/Java/Go/PHP）
- filter_findings 集成
"""

import pytest

from src.scanner.false_positive_manager import InlineSuppressor


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------


def make_finding(line: int, vuln_type: str) -> dict:
    return {"line": line, "type": vuln_type, "details": "test finding"}


# ---------------------------------------------------------------------------
# 测试：行末通配符 # aegis-ignore
# ---------------------------------------------------------------------------


class TestWildcardSuppression:
    def test_hash_style_inline_wildcard(self):
        code = "result = requests.get(user_url)  # aegis-ignore\n"
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(1, "SSRF")
        assert sup.is_suppressed(1, "SQL_INJECTION")

    def test_slash_style_inline_wildcard(self):
        code = "fetch(userUrl);  // aegis-ignore\n"
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(1, "SSRF")
        assert sup.is_suppressed(1, "XSS_RISK")

    def test_no_annotation_not_suppressed(self):
        code = "result = requests.get(user_url)\n"
        sup = InlineSuppressor(code)
        assert not sup.is_suppressed(1, "SSRF")

    def test_other_line_not_suppressed(self):
        code = "safe_line = 1\nresult = requests.get(user_url)  # aegis-ignore\n"
        sup = InlineSuppressor(code)
        assert not sup.is_suppressed(1, "SSRF")  # line 1 is safe
        assert sup.is_suppressed(2, "SSRF")       # line 2 is suppressed


# ---------------------------------------------------------------------------
# 测试：行末类型特定 # aegis-ignore: VULN_TYPE
# ---------------------------------------------------------------------------


class TestTypedSuppression:
    def test_hash_typed_matches(self):
        code = "result = requests.get(user_url)  # aegis-ignore: SSRF\n"
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(1, "SSRF")

    def test_hash_typed_not_matches_other_type(self):
        code = "result = requests.get(user_url)  # aegis-ignore: SSRF\n"
        sup = InlineSuppressor(code)
        assert not sup.is_suppressed(1, "SQL_INJECTION")

    def test_slash_typed_matches(self):
        code = 'const r = fetch(url); // aegis-ignore: SSRF\n'
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(1, "SSRF")

    def test_case_insensitive_vuln_type(self):
        code = "result = requests.get(user_url)  # aegis-ignore: ssrf\n"
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(1, "SSRF")
        assert sup.is_suppressed(1, "ssrf")


# ---------------------------------------------------------------------------
# 测试：行上方前缀注释
# ---------------------------------------------------------------------------


class TestPrefixComment:
    def test_prefix_line_suppresses_next_line(self):
        code = "# aegis-ignore\nresult = requests.get(user_url)\n"
        sup = InlineSuppressor(code)
        # Comment is on line 1, target code is on line 2
        assert sup.is_suppressed(2, "SSRF")

    def test_prefix_line_typed_suppresses_next_line(self):
        code = "# aegis-ignore: SQL_INJECTION\ncursor.execute(query)\n"
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(2, "SQL_INJECTION")
        assert not sup.is_suppressed(2, "XSS_RISK")

    def test_prefix_does_not_suppress_line_after_next(self):
        code = "# aegis-ignore\nresult = requests.get(user_url)\nsafe_call()\n"
        sup = InlineSuppressor(code)
        assert sup.is_suppressed(2, "SSRF")
        assert not sup.is_suppressed(3, "SSRF")


# ---------------------------------------------------------------------------
# 测试：filter_findings 集成
# ---------------------------------------------------------------------------


class TestFilterFindings:
    def test_filters_suppressed_finding(self):
        code = "result = requests.get(user_url)  # aegis-ignore\n"
        sup = InlineSuppressor(code)
        findings = [make_finding(1, "SSRF"), make_finding(1, "SQL_INJECTION")]
        result = sup.filter_findings(findings)
        assert result == []

    def test_keeps_non_suppressed_finding(self):
        code = "result = requests.get(user_url)\n"
        sup = InlineSuppressor(code)
        findings = [make_finding(1, "SSRF")]
        result = sup.filter_findings(findings)
        assert len(result) == 1

    def test_typed_suppression_keeps_other_types(self):
        code = "result = requests.get(user_url)  # aegis-ignore: SSRF\n"
        sup = InlineSuppressor(code)
        findings = [make_finding(1, "SSRF"), make_finding(1, "SQL_INJECTION")]
        result = sup.filter_findings(findings)
        assert len(result) == 1
        assert result[0]["type"] == "SQL_INJECTION"

    def test_empty_code_no_suppression(self):
        sup = InlineSuppressor("")
        findings = [make_finding(1, "SSRF")]
        result = sup.filter_findings(findings)
        assert len(result) == 1

    def test_multiline_code_selective_suppression(self):
        code = (
            "safe_call()\n"                                  # line 1
            "result = requests.get(url1)  # aegis-ignore\n"  # line 2
            "result2 = requests.get(url2)\n"                 # line 3
        )
        sup = InlineSuppressor(code)
        findings = [
            make_finding(2, "SSRF"),
            make_finding(3, "SSRF"),
        ]
        result = sup.filter_findings(findings)
        assert len(result) == 1
        assert result[0]["line"] == 3
