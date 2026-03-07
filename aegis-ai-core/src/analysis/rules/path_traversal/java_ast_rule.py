"""
path_traversal.java_ast_rule

Java 路径穿越 AST/污点规则。

检测目标：
- 用户可控输入流入 File/FileInputStream 等文件访问 API；
- 依赖统一污点图 TaintGraph 与 Java Sink 注册（PATH_TRAVERSAL 类别）。
"""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule


class JavaPathTraversalAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Java 路径穿越检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="PATH_TRAVERSAL_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """Path Traversal 规则仅在 after_file 中读取 TaintGraph。"""
        return

    def after_file(self, context: AnalysisContext) -> None:
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: set[str] = set()

        try:
            paths: list[Any] = graph.find_paths_to_sinks()
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
            if category != "path_traversal":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Java 代码中用户可控输入流入文件系统访问（如 new File()/FileInputStream），"
                "且未检测到路径规范化或白名单校验，存在目录穿越风险。"
            )

            finding: dict[str, Any] = {
                "type": "PATH_TRAVERSAL",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["JavaPathTraversalAstRule"]
