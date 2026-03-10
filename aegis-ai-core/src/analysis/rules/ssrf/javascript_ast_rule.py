"""
ssrf.javascript_ast_rule

JavaScript/TypeScript SSRF（Server-Side Request Forgery）AST/污点规则。

检测目标：
- 用户可控输入流入 fetch、axios、http.get、https.get、request 等 HTTP 请求函数；
- 依赖统一污点图 TaintGraph 与 JS Sink 注册（SSRF 类别）。

CWE: CWE-918
OWASP: A10:2021 – Server-Side Request Forgery (SSRF)
"""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, safe_find_paths


class JavaScriptSSRFAstRule(SecurityRule):
    """
    基于 TaintGraph 的 JavaScript/TypeScript SSRF 检测规则。

    报告条件：存在污点路径，用户可控输入流入 HTTP 请求函数（fetch/axios/http.get 等），
    且路径未被净化（URL 白名单校验、域名过滤等）。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SSRF_JS_TAINT",
            severity="High",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """SSRF 规则仅在 after_file 中读取 TaintGraph。"""
        return

    def after_file(self, context: AnalysisContext) -> None:
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: set[str] = set()

        paths = safe_find_paths(graph, self.rule_id)

        for path in paths:
            if getattr(path, "is_sanitized", False):
                continue

            sink = getattr(path, "sink_node", None)
            source = getattr(path, "source_node", None)
            if sink is None or source is None:
                continue

            sink_id = getattr(sink, "id", "")
            if not sink_id or sink_id in reported_sinks:
                continue

            category = (sink.extras or {}).get("category") if hasattr(sink, "extras") else None
            if category != "ssrf":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 JavaScript/TypeScript 代码中用户可控输入直接用于 HTTP 请求目标 URL"
                "（fetch/axios/http.get 等），可能导致 SSRF 漏洞（CWE-918）。"
                "建议使用 URL 协议和域名白名单，拒绝访问内网地址（169.254.x.x、10.x.x.x、127.x.x.x 等）。"
            )

            finding: dict[str, Any] = {
                "type": "SSRF",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "cwe": "CWE-918",
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["JavaScriptSSRFAstRule"]
