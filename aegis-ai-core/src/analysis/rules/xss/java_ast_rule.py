"""
xss.java_ast_rule

Java XSS 风险 AST/污点规则。

检测目标：
- 用户可控输入通过 Servlet API 写入响应（response.getWriter().write 等）；
- 依赖统一污点图 TaintGraph 与 Java Sink 注册（XSS 类别）。
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from ...base import AnalysisContext, SecurityRule


class JavaXSSAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Java XSS 风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="XSS_RISK_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """XSS 规则仅在 after_file 中读取 TaintGraph。"""
        return

    def after_file(self, context: AnalysisContext) -> None:
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: Set[str] = set()

        try:
            paths: List[Any] = graph.find_paths_to_sinks()
        except Exception:
            return

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
            if category != "xss":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Java 代码中用户可控输入直接写入 HTTP 响应（如 response.getWriter().write），"
                "且未检测到 HtmlUtils/ESAPI 等 HTML 转义，存在 XSS 风险。"
            )

            finding: Dict[str, Any] = {
                "type": "XSS_RISK",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["JavaXSSAstRule"]

