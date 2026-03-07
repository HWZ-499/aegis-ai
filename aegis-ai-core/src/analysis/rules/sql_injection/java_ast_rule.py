"""
sql_injection.java_ast_rule

Java SQL 注入 AST/污点规则。

检测目标（基于统一污点图 TaintGraph）：
- 用户可控输入流入 JDBC Statement.execute / Connection.createStatement 等 SQL 执行点；
- 结合 SourceSinkRegistry 中的 Java Sources/Sinks + Sanitizer 感知（PreparedStatement）。
"""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule


class JavaSQLInjectionAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Java SQL 注入检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="SQL_INJECTION_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        Java 版 SQLi 规则不依赖逐节点扫描，仅在 after_file 阶段读取 TaintGraph。
        """
        return

    def after_file(self, context: AnalysisContext) -> None:
        """
        在文件遍历完成后，根据 TaintGraph 中的 Source→Sink 路径生成 SQLI 告警。
        """
        graph = getattr(context, "taint_graph", None)
        any_reported = False
        if graph is not None:
            # 避免同一 Sink 重复报多条路径
            reported_sinks: set[str] = set()

            try:
                paths: list[Any] = graph.find_paths_to_sinks()
            except Exception:
                paths = []

            for path in paths:
                # 跳过已净化路径
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
                    "检测到 Java 代码中用户可控输入流入 SQL 执行（Statement/Connection.execute 等），"
                    "且未检测到参数化查询或有效净化，存在 SQL 注入风险，建议使用 PreparedStatement 或 ORM 参数绑定。"
                )

                finding: dict[str, Any] = {
                    "type": "SQL_INJECTION",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line_no,
                    "details": details,
                    "source_expr": src_expr,
                    "sink_expr": sink_expr,
                }
                context.add_finding(finding)
                any_reported = True

        if any_reported:
            return

        # Fallback：若 TaintGraph 未产生 SQLi 路径，使用源码模式匹配兜底常见模式
        source_code = context.extras.get("source") or ""
        if not source_code:
            return

        pattern = re.compile(
            r"""(?im)\bexecute(?:Query|Update)?\s*\([^;]*request\.getParameter\s*\(""",
        )

        for m in pattern.finditer(source_code):
            line_no = source_code[: m.start()].count("\n") + 1
            sink_expr = m.group(0).strip()
            details = (
                "检测到 Java 代码中使用 request.getParameter 拼接 SQL 语句并调用 execute/executeQuery，"
                "存在 SQL 注入风险，建议改用 PreparedStatement 或 ORM 参数绑定。"
            )
            finding: dict[str, Any] = {
                "type": "SQL_INJECTION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": "request.getParameter(...)",
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)


__all__ = ["JavaSQLInjectionAstRule"]
