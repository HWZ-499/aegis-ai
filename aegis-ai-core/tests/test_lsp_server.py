"""
test_lsp_server.py - Aegis AI LSP Server 单元测试

测试内容：
1. finding -> Diagnostic 映射逻辑（severity / line / message / code）
2. 语言检测（扩展名 -> 语言标识符）
3. URI 转换（file:// URI -> 本地路径）
4. 空文件 / 无漏洞文件不产生 Diagnostic
5. 含漏洞文件正确产生 Diagnostic
"""

import pytest
from lsprotocol import types as lsp

from src.lsp.server import (
    detect_language,
    finding_to_diagnostic,
    scan_document,
    uri_to_filepath,
    SEVERITY_MAP,
    _get_remediation_for_rule,
    _remediation_to_comment_text,
)

# 单元测试用文档 URI（finding_to_diagnostic 需要 document_uri 以映射 related_locations）
DUMMY_URI = "file:///dummy"


# ============================================================================
# 1. finding -> Diagnostic 映射
# ============================================================================


class TestFindingToDiagnostic:
    """测试 finding dict 到 LSP Diagnostic 的转换。"""

    def test_basic_mapping(self):
        """基本字段映射：line / severity / message / code / source。"""
        finding = {
            "type": "SQL_INJECTION",
            "severity": "High",
            "line": 10,
            "details": "Potential SQL injection via string concatenation",
            "file": "app.js",
        }
        diag = finding_to_diagnostic(finding, DUMMY_URI)

        assert diag.range.start.line == 9  # LSP 行号 0-based
        assert diag.range.start.character == 0
        assert diag.range.end.line == 9
        assert diag.range.end.character == 999
        assert diag.severity == lsp.DiagnosticSeverity.Error
        assert "Potential SQL injection via string concatenation" in diag.message
        assert "修复建议" in diag.message
        assert "建议修复代码" in diag.message
        assert diag.code == "SQL_INJECTION"
        assert diag.source == "Aegis AI"

    def test_critical_severity(self):
        """Critical 严重等级映射为 Error。"""
        finding = {"severity": "Critical", "line": 1, "details": "critical issue"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.severity == lsp.DiagnosticSeverity.Error

    def test_medium_severity(self):
        """Medium 严重等级映射为 Warning。"""
        finding = {"severity": "Medium", "line": 5, "details": "medium issue"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.severity == lsp.DiagnosticSeverity.Warning

    def test_low_severity(self):
        """Low 严重等级映射为 Information。"""
        finding = {"severity": "Low", "line": 3, "details": "low issue"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.severity == lsp.DiagnosticSeverity.Information

    def test_info_severity(self):
        """Info 严重等级映射为 Hint。"""
        finding = {"severity": "Info", "line": 1, "details": "info issue"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.severity == lsp.DiagnosticSeverity.Hint

    def test_unknown_severity_defaults_to_warning(self):
        """未知严重等级默认映射为 Warning。"""
        finding = {"severity": "Unknown", "line": 1, "details": "unknown"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.severity == lsp.DiagnosticSeverity.Warning

    def test_missing_line_defaults_to_zero(self):
        """缺少 line 字段时默认为第 0 行（LSP 0-based）。"""
        finding = {"severity": "High", "details": "no line"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.range.start.line == 0

    def test_line_zero_clamped(self):
        """line=0 时不会变成负数。"""
        finding = {"severity": "High", "line": 0, "details": "line zero"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.range.start.line == 0

    def test_fallback_message(self):
        """没有 details 时回退到 message 字段。"""
        finding = {"severity": "High", "line": 1, "message": "fallback msg"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.message == "fallback msg"

    def test_default_message(self):
        """既没有 details 也没有 message 时使用默认消息。"""
        finding = {"severity": "High", "line": 1}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.message == "Security issue detected"

    def test_missing_type_defaults_to_unknown(self):
        """缺少 type 字段时 code 为 UNKNOWN。"""
        finding = {"severity": "High", "line": 1, "details": "test"}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.code == "UNKNOWN"


# ============================================================================
# 2. 语言检测
# ============================================================================


class TestDetectLanguage:
    """测试文件扩展名到语言标识符的映射。"""

    @pytest.mark.parametrize(
        "path, expected",
        [
            ("app.js", "javascript"),
            ("component.jsx", "javascript"),
            ("index.mjs", "javascript"),
            ("utils.cjs", "javascript"),
            ("app.ts", "typescript"),
            ("component.tsx", "typescript"),
            ("script.py", "python"),
            ("script.pyw", "python"),
        ],
    )
    def test_supported_extensions(self, path, expected):
        """已知扩展名正确映射。"""
        assert detect_language(path) == expected

    @pytest.mark.parametrize(
        "path",
        [
            "readme.md",
            "config.json",
            "style.css",
            "Makefile",
            "image.png",
            "data.yaml",
        ],
    )
    def test_unsupported_extensions(self, path):
        """不支持的扩展名返回 None。"""
        assert detect_language(path) is None

    def test_case_insensitive(self):
        """扩展名大小写不敏感。"""
        assert detect_language("App.JS") == "javascript"
        assert detect_language("Main.PY") == "python"
        assert detect_language("App.TS") == "typescript"

    def test_full_path(self):
        """完整路径也能正确检测。"""
        assert detect_language("/home/user/project/src/app.js") == "javascript"
        assert detect_language("C:\\Users\\foo\\bar.py") == "python"


# ============================================================================
# 3. URI 转换
# ============================================================================


class TestUriToFilepath:
    """测试 file:// URI 到本地文件路径的转换。"""

    def test_unix_path(self):
        """Unix 风格 URI。"""
        uri = "file:///home/user/project/app.js"
        assert uri_to_filepath(uri) == "/home/user/project/app.js"

    def test_windows_path(self):
        """Windows 风格 URI（驱动器号编码）。"""
        uri = "file:///c%3A/Users/foo/bar.js"
        result = uri_to_filepath(uri)
        assert result == "c:/Users/foo/bar.js"

    def test_windows_path_uppercase_drive(self):
        """Windows URI 驱动器号大写。"""
        uri = "file:///C:/Users/foo/bar.py"
        result = uri_to_filepath(uri)
        assert result == "C:/Users/foo/bar.py"

    def test_spaces_in_path(self):
        """路径中包含空格。"""
        uri = "file:///home/user/my%20project/app.js"
        result = uri_to_filepath(uri)
        assert result == "/home/user/my project/app.js"


# ============================================================================
# 4. scan_document 集成测试
# ============================================================================


class TestScanDocument:
    """测试 scan_document 函数的集成行为。"""

    def test_empty_file_no_findings(self):
        """空文件不产生任何 finding。"""
        findings = scan_document("", "test.js")
        assert findings == []

    def test_safe_code_no_findings(self):
        """安全代码不产生 finding。"""
        safe_code = """
const x = 1 + 2;
console.log(x);
"""
        findings = scan_document(safe_code, "safe.js")
        assert findings == []

    def test_unsupported_language_no_findings(self):
        """不支持的语言不产生 finding。"""
        findings = scan_document("some content", "readme.md")
        assert findings == []

    def test_vulnerable_js_produces_findings(self):
        """含漏洞的 JavaScript 代码应产生 finding。"""
        vulnerable_code = """
const userInput = req.query.name;
eval(userInput);
"""
        findings = scan_document(vulnerable_code, "vuln.js")
        assert len(findings) > 0
        # 至少有一个 RCE 类型的发现
        types = [f.get("type", "") for f in findings]
        assert any("RCE" in t for t in types)

    def test_vulnerable_python_produces_findings(self):
        """含漏洞的 Python 代码应产生 finding。"""
        vulnerable_code = """
import os
user_input = input()
os.system(user_input)
"""
        findings = scan_document(vulnerable_code, "vuln.py")
        assert len(findings) > 0

    def test_safe_python_no_findings(self):
        """安全的 Python 代码不产生 finding。"""
        safe_code = """
x = 1 + 2
print(x)
"""
        findings = scan_document(safe_code, "safe.py")
        assert findings == []

    def test_typescript_detection(self):
        """TypeScript 文件被正确识别并扫描。"""
        vulnerable_code = """
const userInput = req.query.name;
eval(userInput);
"""
        findings = scan_document(vulnerable_code, "vuln.ts")
        assert len(findings) > 0


# ============================================================================
# 5. severity 映射完整性
# ============================================================================


class TestSeverityMap:
    """测试 severity 映射的完整性。"""

    def test_all_expected_severities_present(self):
        """所有预期的严重等级都有映射。"""
        expected = ["Critical", "critical", "High", "high", "Medium", "medium",
                    "Low", "low", "Info", "info"]
        for sev in expected:
            assert sev in SEVERITY_MAP, f"Missing severity mapping: {sev}"

    def test_error_severities(self):
        """Critical 和 High 都映射为 Error。"""
        assert SEVERITY_MAP["Critical"] == lsp.DiagnosticSeverity.Error
        assert SEVERITY_MAP["High"] == lsp.DiagnosticSeverity.Error

    def test_warning_severity(self):
        """Medium 映射为 Warning。"""
        assert SEVERITY_MAP["Medium"] == lsp.DiagnosticSeverity.Warning

    def test_info_severity(self):
        """Low 映射为 Information。"""
        assert SEVERITY_MAP["Low"] == lsp.DiagnosticSeverity.Information

    def test_hint_severity(self):
        """Info 映射为 Hint。"""
        assert SEVERITY_MAP["Info"] == lsp.DiagnosticSeverity.Hint


# ============================================================================
# 6. M1 Code Action 修复建议
# ============================================================================


class TestCodeActionRemediation:
    """M1：内置修复建议与注释文案。"""

    def test_get_remediation_nosql(self):
        """NOSQL_INJECTION 有内置建议。"""
        data = _get_remediation_for_rule("NOSQL_INJECTION")
        assert isinstance(data, dict)
        assert "description" in data
        assert "remediation" in data
        assert "MongoDB" in data["description"] or "NoSQL" in data["description"]

    def test_get_remediation_unknown_returns_empty(self):
        """未知规则返回空 dict。"""
        assert _get_remediation_for_rule("UNKNOWN_RULE") == {}

    def test_remediation_to_comment_contains_rule_id(self):
        """注释文案包含规则 ID。"""
        text = _remediation_to_comment_text("NOSQL_INJECTION")
        assert "Aegis" in text
        assert "NOSQL_INJECTION" in text
        assert "修复" in text or "建议" in text

    def test_rce_has_suggested_code_for_apply_example(self):
        """RCE_COMMAND_EXEC 有 suggested_code，供「应用示例代码」Code Action 使用。"""
        data = _get_remediation_for_rule("RCE_COMMAND_EXEC")
        assert isinstance(data, dict)
        assert "suggested_code" in data
        assert isinstance(data["suggested_code"], str)
        assert "require(" in data["suggested_code"]
        assert "crypto" in data["suggested_code"]
