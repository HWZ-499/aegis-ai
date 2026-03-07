"""
xss.go_ast_rule

Go XSS 风险 AST/污点规则。

检测目标：
- 用户可控输入通过 fmt.Fprintf 向 HTTP ResponseWriter 输出；
- 依赖统一污点图 TaintGraph 与 Go Sink 注册（XSS 类别）。
"""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, safe_find_paths


class GoXSSAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Go XSS 风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="XSS_RISK_GO_TAINT",
            severity="High",
            languages=["go"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """XSS 规则仅在 after_file 中读取 TaintGraph。"""
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
            if category != "xss":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Go 代码中用户可控输入通过 fmt.Fprintf 输出到响应，"
                "且未检测到 template.HTMLEscapeString 等转义，存在 XSS 风险。"
            )

            finding: dict[str, Any] = {
                "type": "XSS_RISK",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["GoXSSAstRule"]
