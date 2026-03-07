"""
open_redirect.go_ast_rule

Go Open Redirect AST/污点规则。

检测目标：
- 用户可控输入流入 http.Redirect 等重定向 API；
- 依赖统一污点图 TaintGraph 与 Go Sink 注册（OPEN_REDIRECT 类别）。
"""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, safe_find_paths


class GoOpenRedirectAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Go Open Redirect 检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="OPEN_REDIRECT_GO_TAINT",
            severity="Medium",
            languages=["go"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """Open Redirect 规则仅在 after_file 中读取 TaintGraph。"""
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
            if category != "open_redirect":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Go 代码中用户可控输入直接用于 http.Redirect 跳转目标，"
                "可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。"
            )

            finding: dict[str, Any] = {
                "type": "OPEN_REDIRECT",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["GoOpenRedirectAstRule"]
