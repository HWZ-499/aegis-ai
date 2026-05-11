"""
test_lsp_server.py - Aegis AI LSP Server 单元测试

测试内容：
1. finding -> Diagnostic 映射逻辑（severity / line / message / code）
2. 语言检测（扩展名 -> 语言标识符）
3. URI 转换（file:// URI -> 本地路径）
4. 空文件 / 无漏洞文件不产生 Diagnostic
5. 含漏洞文件正确产生 Diagnostic
"""

from pathlib import Path

import pytest
from lsprotocol import types as lsp
from pygls.protocol.language_server import _prepare_command_arguments

from src.lsp import server as lsp_server
from src.lsp.server import (
    SEVERITY_MAP,
    WorkspaceContext,
    _discover_workspace_scan_files,
    _find_aegis_comment_block,
    _get_remediation_for_rule,
    _is_path_excluded,
    _remediation_to_comment_text,
    detect_language,
    finding_to_diagnostic,
    scan_document,
    uri_to_filepath,
)
from src.scanner.baseline import Baseline

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

    def test_message_includes_action_guidance(self):
        """诊断悬停文案应明确区分真实修复、注释建议和 baseline 抑制。"""
        finding = {
            "type": "SQL_INJECTION",
            "severity": "High",
            "line": 3,
            "details": "Potential SQL injection via string concatenation",
            "file": "app.js",
        }

        diag = finding_to_diagnostic(
            finding,
            DUMMY_URI,
            source_code='const query = "SELECT * FROM users WHERE id = " + userId;',
            file_path="app.js",
        )

        assert "Aegis 可用操作" in diag.message
        assert "应用 AI 精准修复: 会替换代码并触发复扫" in diag.message
        assert "插入修复建议注释: 只会插入建议，不会修复代码" in diag.message
        assert "Ignore / Add to baseline: 接受并隐藏当前问题，不是修复代码" in diag.message

    def test_unknown_rule_explains_when_example_fix_is_unavailable(self):
        """没有安全替换模板时，hover 应解释为什么没有示例修复动作。"""
        finding = {
            "type": "UNKNOWN_RULE",
            "severity": "High",
            "line": 8,
            "details": "Unknown issue",
            "file": "mystery.py",
        }

        diag = finding_to_diagnostic(finding, DUMMY_URI)

        assert "应用示例修复代码: 当前规则没有安全替换模板" in diag.message

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
        assert diag.message.startswith("fallback msg")

    def test_default_message(self):
        """既没有 details 也没有 message 时使用默认消息。"""
        finding = {"severity": "High", "line": 1}
        diag = finding_to_diagnostic(finding, DUMMY_URI)
        assert diag.message.startswith("Security issue detected")

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
        expected = ["Critical", "critical", "High", "high", "Medium", "medium", "Low", "low", "Info", "info"]
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

    def test_remediation_to_comment_uses_python_comment_prefix(self):
        """Python 文件中的修复建议注释必须使用 #。"""
        text = _remediation_to_comment_text("NOSQL_INJECTION", language="python")
        assert text.splitlines()[0].startswith("# ")

    def test_rce_has_suggested_code_for_apply_example(self):
        """RCE_COMMAND_EXEC 有 suggested_code，供「应用示例代码」Code Action 使用。"""
        data = _get_remediation_for_rule("RCE_COMMAND_EXEC")
        assert isinstance(data, dict)
        assert "suggested_code" in data
        assert isinstance(data["suggested_code"], str)
        assert "require(" in data["suggested_code"]
        assert "crypto" in data["suggested_code"]


class TestPathExcludeMatching:
    """LSP 侧也应遵守排除模式，避免手动扫描与项目扫描语义分叉。"""

    def test_relative_glob_match(self):
        assert (
            _is_path_excluded(
                "C:/repo/public/app.js",
                "C:/repo",
                ["**/public/**"],
            )
            is True
        )

    def test_dependency_directory_match(self):
        assert (
            _is_path_excluded(
                "C:/repo/node_modules/pkg/index.js",
                "C:/repo",
                ["**/node_modules/**"],
            )
            is True
        )

    def test_business_directory_not_excluded_by_default_like_pattern_gap(self):
        assert (
            _is_path_excluded(
                "C:/repo/lib/service.py",
                "C:/repo",
                ["**/node_modules/**", "**/dist/**"],
            )
            is False
        )


class TestWorkspaceScanDiscovery:
    """M3：workspace scan 应发现未打开的 workspace 源码文件。"""

    def test_discovers_unopened_workspace_source_files(self, tmp_path: Path):
        src_file = tmp_path / "src" / "app.js"
        src_file.parent.mkdir(parents=True)
        src_file.write_text("eval(req.body.code);\n", encoding="utf-8")
        ignored_file = tmp_path / "node_modules" / "pkg" / "index.js"
        ignored_file.parent.mkdir(parents=True)
        ignored_file.write_text("eval(req.body.code);\n", encoding="utf-8")

        files = _discover_workspace_scan_files(str(tmp_path), ["**/node_modules/**"])

        assert files == [src_file.resolve()]

    def test_workspace_context_records_root_even_without_cross_file(self, tmp_path: Path):
        ctx = WorkspaceContext()
        ctx.configure({"experimental_cross_file": False})

        ctx.build_graph_async(str(tmp_path))

        assert ctx._project_path == str(tmp_path.resolve())


class TestInsertedCommentRemoval:
    """Aegis 生成的注释块需要可识别并支持撤回。"""

    def test_find_python_comment_block(self):
        lines = [
            "# Aegis 修复建议 (SQL_INJECTION):",
            "# 使用参数化查询",
            "# 参考: https://example.com",
            "cursor.execute(query)",
        ]

        block = _find_aegis_comment_block(lines, 1)

        assert block == (0, 3)

    def test_find_ai_comment_block(self):
        lines = [
            "const query = userInput;",
            "// Aegis AI 修复建议 (XSS_RISK) 置信度 50%",
            "// 需人工复核",
            "// 建议修改为:",
            "// res.send(escapeHtml(name));",
            "res.send(name);",
        ]

        block = _find_aegis_comment_block(lines, 3)

        assert block == (1, 5)

    def test_non_aegis_comments_are_not_removed(self):
        lines = [
            "# normal comment",
            "# another comment",
            "print('safe')",
        ]

        block = _find_aegis_comment_block(lines, 0)

        assert block is None

    def test_adjacent_user_comments_are_not_included_in_removal_block(self):
        lines = [
            "# user comment",
            "# Aegis 修复建议 (SQL_INJECTION):",
            "# 使用参数化查询",
            "cursor.execute(query)",
        ]

        block = _find_aegis_comment_block(lines, 2)

        assert block == (1, 3)


class TestBaselineCommand:
    """VS Code Code Action 触发的 baseline 命令应按 LSP 参数语义执行。"""

    def test_add_to_baseline_accepts_single_lsp_payload(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        project_root = tmp_path
        target = project_root / "app.js"
        target.write_text('const apiKey = "sk-test";\n', encoding="utf-8")
        monkeypatch.setattr(lsp_server._workspace_ctx, "_project_path", str(project_root))

        server = lsp_server.create_server()
        handler = server.protocol.fm.commands["aegis.addToBaseline"]
        params = lsp.ExecuteCommandParams(
            command="aegis.addToBaseline",
            arguments=[
                {
                    "uri": target.as_uri(),
                    "rule_id": "HARDCODED_CREDENTIALS",
                    "line": 1,
                    "message": "hardcoded credential",
                }
            ],
        )

        args, kwargs = _prepare_command_arguments(handler, params, server.protocol._converter)
        handler(*args, **kwargs)

        baseline = Baseline.load(project_root / ".aegis-baseline.json")
        entries = baseline.list_entries()
        assert len(entries) == 1
        assert entries[0].rule_id == "HARDCODED_CREDENTIALS"
        assert entries[0].file_path == "app.js"
        assert entries[0].line == 1
