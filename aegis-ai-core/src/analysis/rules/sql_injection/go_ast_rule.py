"""
sql_injection.go_ast_rule

Go SQL 注入 AST/污点规则。

检测目标（基于统一污点图 TaintGraph）：
- 用户可控输入流入 database/sql 的 Query/Exec 等 SQL 执行点。
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from ...base import AnalysisContext, SecurityRule


class GoSQLInjectionAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Go SQL 注入检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQL_INJECTION_GO_TAINT",
            severity="High",
            languages=["go"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """Go 版 SQLi 规则仅在 after_file 中读取 TaintGraph。"""
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
            if category != "sql_injection":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Go 代码中用户可控输入流入 database/sql Query/Exec，"
                "且未检测到占位符参数绑定，存在 SQL 注入风险。"
            )

            finding: Dict[str, Any] = {
                "type": "SQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["GoSQLInjectionAstRule"]

