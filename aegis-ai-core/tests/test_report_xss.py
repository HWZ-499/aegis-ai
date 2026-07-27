"""
test_report_xss.py - 报告生成器 XSS 防护测试

验证报告生成器不会将恶意 payload 原样注入 HTML，
即所有动态内容都经过 html.escape() 转义。
"""

import pytest

from src.scanner.report_generator import ReportGenerator


@pytest.fixture
def generator() -> ReportGenerator:
    """创建一个报告生成器实例。"""
    return ReportGenerator("Test Project")


@pytest.fixture
def xss_results() -> dict:
    """包含 XSS payload 的模拟扫描结果。"""
    return {
        "<img src=x onerror=alert(1)>": [
            {
                "line": 1,
                "type": "<script>alert('xss')</script>",
                "severity": "High",
                "details": "Payload: <img src=x onerror=alert('stolen')>",
                "content": "var x = '<script>document.cookie</script>'",
            }
        ]
    }


@pytest.fixture
def xss_stats() -> dict:
    """基本统计数据。"""
    return {
        "total_files": 1,
        "scanned_files": 1,
        "files_with_issues": 1,
        "total_issues": 1,
        "scan_time": 0.5,
        "severity_stats": {"High": 1},
    }


class TestHTMLReportXSSProtection:
    """验证基础 HTML 报告的 XSS 防护。"""

    def test_file_path_escaped(self, generator, xss_results, xss_stats) -> None:
        """文件路径中的 HTML 特殊字符必须被转义。"""
        html = generator.generate_html(xss_results, xss_stats)
        # 原始文件路径 <img src=x onerror=alert(1)> 必须被转义
        assert "<img src=x onerror=alert(1)>" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html

    def test_type_escaped(self, generator, xss_results, xss_stats) -> None:
        """漏洞类型字段中的 HTML 必须被转义。"""
        html = generator.generate_html(xss_results, xss_stats)
        assert "<script>alert('xss')</script>" not in html
        assert "&lt;script&gt;" in html

    def test_details_escaped(self, generator, xss_results, xss_stats) -> None:
        """详情字段中的恶意 HTML 必须被转义。"""
        html = generator.generate_html(xss_results, xss_stats)
        assert "onerror=alert('stolen')" not in html

    def test_content_escaped(self, generator, xss_results, xss_stats) -> None:
        """代码内容字段中的 <script> 标签必须被转义。"""
        html = generator.generate_html(xss_results, xss_stats)
        # 不能出现未转义的 <script>
        raw_script_count = html.count("<script>")
        assert raw_script_count == 0, f"发现 {raw_script_count} 个未转义的 <script> 标签"

    def test_project_name_escaped(self, xss_stats) -> None:
        """项目名称中的 XSS 也必须被转义。"""
        gen = ReportGenerator("<script>alert('name')</script>")
        html = gen.generate_html({}, xss_stats)
        assert "<script>alert('name')</script>" not in html
        assert "&lt;script&gt;" in html


class TestEnhancedHTMLReportXSSProtection:
    """验证增强版 HTML 报告的 XSS 防护。"""

    def test_remediation_escaped(self, generator, xss_stats) -> None:
        """RAG 修复建议字段中的 HTML 必须被转义。"""
        results = {
            "test.js": [
                {
                    "line": 10,
                    "type": "XSS",
                    "severity": "High",
                    "details": "XSS found",
                    "remediation": {
                        "cwe": "CWE-79",
                        "description": "<script>alert('desc')</script>",
                        "suggestions": ["Use <b>escape</b> function"],
                        "references": ["https://example.com/<script>"],
                    },
                }
            ]
        }
        html = generator.generate_html_enhanced(results, xss_stats)
        # description 中的 <script> 必须被转义
        assert "<script>alert('desc')</script>" not in html
        # suggestions 中的 <b> 标签也必须被转义
        assert "<b>escape</b>" not in html
        assert "&lt;b&gt;escape&lt;/b&gt;" in html

    def test_cve_info_escaped(self, generator, xss_stats) -> None:
        """CVE 信息中的恶意内容必须被转义。"""
        results = {
            "test.js": [
                {
                    "line": 1,
                    "type": "INJECTION",
                    "severity": "Critical",
                    "details": "Found",
                    "related_cves": [
                        {
                            "cve_id": "CVE-2024-<script>alert(1)</script>",
                            "relevance": 0.9,
                            "description": "<img onerror=alert(1)>",
                        }
                    ],
                }
            ]
        }
        html = generator.generate_html_enhanced(results, xss_stats)
        assert "<script>alert(1)</script>" not in html
        assert "<img onerror=alert(1)>" not in html


class TestMarkdownReport:
    """验证 Markdown 报告基本功能正常。"""

    def test_markdown_generation(self, generator) -> None:
        """Markdown 报告应正常生成，包含标题和摘要。"""
        results = {
            "app.js": [
                {
                    "line": 5,
                    "type": "SQL_INJECTION",
                    "severity": "High",
                    "details": "SQL Injection found",
                }
            ]
        }
        stats = {"total_files": 1, "scanned_files": 1, "files_with_issues": 1, "total_issues": 1, "scan_time": 0.1}
        md = generator.generate_markdown(results, stats)
        assert "安全扫描报告" in md
        assert "app.js" in md
        assert "SQL_INJECTION" in md


class TestJSONReport:
    """验证 JSON 报告基本功能正常。"""

    def test_json_valid(self, generator) -> None:
        """JSON 报告应是合法 JSON。"""
        import json

        results = {"test.py": [{"line": 1, "type": "TEST", "severity": "Low", "details": "test"}]}
        stats = {"total_files": 1, "scanned_files": 1}
        output = generator.generate_json(results, stats)
        data = json.loads(output)
        assert data["project_name"] == "Test Project"
        assert data["results"]["test.py"][0]["type"] == "TEST"

    def test_json_includes_partial_scan_errors(self, generator) -> None:
        """JSON report must make partial scans machine-readable."""
        import json

        stats = {
            "total_files": 1,
            "scanned_files": 1,
            "files_with_issues": 0,
            "total_issues": 0,
            "scan_time": 0.1,
            "partial": True,
            "error_count": 1,
            "errors": [{"file": "app.py", "phase": "scan", "message": "parser unavailable"}],
        }
        output = generator.generate_json({}, stats)
        data = json.loads(output)

        assert data["summary"]["partial"] is True
        assert data["summary"]["error_count"] == 1
        assert data["errors"] == stats["errors"]


class TestSARIFReport:
    """验证 SARIF 报告中的扫描执行状态。"""

    def test_sarif_includes_partial_scan_notifications(self, generator) -> None:
        """SARIF report must expose scan errors via invocations."""
        import json

        stats = {
            "total_files": 1,
            "scanned_files": 1,
            "files_with_issues": 0,
            "total_issues": 0,
            "partial": True,
            "error_count": 1,
            "errors": [{"file": "app.py", "phase": "scan", "message": "parser unavailable"}],
        }
        output = generator.generate_sarif({}, stats)
        data = json.loads(output)
        invocation = data["runs"][0]["invocations"][0]

        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["message"]["text"] == "app.py: parser unavailable"

    def test_sarif_code_flow_is_structured_and_normalized(self, generator) -> None:
        """Code Flow must use the same rule descriptor and valid SARIF locations."""
        import json

        results = {
            r"src\app.py": [
                {
                    "line": 0,
                    "column": 0,
                    "end_line": 0,
                    "end_column": 0,
                    "type": "SQL_INJECTION",
                    "rule_id": "python.sql-injection.taint",
                    "severity": "High",
                    "details": "tainted query",
                    "cwe_id": "CWE-89",
                    "taint_analysis": {
                        "full_path": {
                            "nodes": [
                                {
                                    "nodeType": "SOURCE",
                                    "name": "request.args",
                                    "filePath": r"src\app.py",
                                    "line": 0,
                                    "column": 0,
                                },
                                {
                                    "nodeType": "SINK",
                                    "name": "cursor.execute",
                                    "filePath": r"C:\repo\src\db.py",
                                    "line": 12,
                                    "column": 4,
                                },
                            ]
                        }
                    },
                }
            ]
        }
        output = generator.generate_sarif(results, {"scanner_version": "1.4.0"})
        data = json.loads(output)
        run = data["runs"][0]
        result = run["results"][0]

        assert result["ruleId"] == "python.sql-injection.taint"
        assert run["tool"]["driver"]["rules"][0]["id"] == result["ruleId"]
        assert run["tool"]["driver"]["rules"][0]["properties"]["vulnerabilityType"] == "SQL_INJECTION"
        assert result["locations"][0]["physicalLocation"] == {
            "artifactLocation": {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            "region": {
                "startLine": 1,
                "startColumn": 1,
                "endLine": 1,
                "endColumn": 1,
            },
        }

        thread_locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert thread_locations[0]["location"]["physicalLocation"] == {
            "artifactLocation": {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 1, "startColumn": 1},
        }
        assert thread_locations[1]["location"]["physicalLocation"] == {
            "artifactLocation": {"uri": "file:///C:/repo/src/db.py"},
            "region": {"startLine": 12, "startColumn": 4},
        }

    def test_sarif_skips_invalid_code_flow_nodes(self, generator) -> None:
        """Malformed path nodes must not create an invalid empty Code Flow."""
        import json

        results = {
            "app.py": [
                {
                    "line": 1,
                    "type": "RCE_COMMAND_EXEC",
                    "severity": "Critical",
                    "taint_analysis": {"full_path": {"nodes": [None, "invalid"]}},
                }
            ]
        }
        result = json.loads(generator.generate_sarif(results, {}))["runs"][0]["results"][0]

        assert "codeFlows" not in result


def test_rule_engine_analyzer_failure_is_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Analyzer failures must propagate so callers can report partial scans."""
    from src.analysis import rule_engine

    class FailingAnalyzer:
        def __init__(self, rules):
            pass

        def analyze(self, code, path):
            raise ValueError("parser unavailable")

    monkeypatch.setitem(rule_engine._LANGUAGE_ANALYZER_MAP, "python", FailingAnalyzer)

    with pytest.raises(RuntimeError, match="python analyzer failed"):
        rule_engine.analyze_python("print('ok')\n", "app.py")
