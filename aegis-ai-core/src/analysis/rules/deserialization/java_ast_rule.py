"""
deserialization.java_ast_rule

Java 反序列化风险 AST/污点规则。

检测目标：
- 用户可控输入流入 ObjectInputStream.readObject 等反序列化 API；
- 依赖统一污点图 TaintGraph 与 Java Sink 注册（DESERIALIZATION 类别）。
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from ...base import AnalysisContext, SecurityRule


class JavaDeserializationAstRule(SecurityRule):
    """
    基于 TaintGraph 的 Java 反序列化风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="DESERIALIZATION_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """反序列化规则仅在 after_file 中读取 TaintGraph。"""
        return

    def after_file(self, context: AnalysisContext) -> None:
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: Set[str] = set()

        # 优先使用完整污点路径（若存在）
        try:
            paths: List[Any] = graph.find_paths_to_sinks()
        except Exception:
            paths = []

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
            if category != "deserialization":
                continue

            reported_sinks.add(sink_id)

            line_no = getattr(sink, "line", 0) or 0
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Java 代码中对不可信数据执行反序列化（如 ObjectInputStream.readObject），"
                "可能导致任意代码执行或敏感对象加载，建议改用安全数据格式（JSON）或加入类型白名单校验。"
            )

            finding: Dict[str, Any] = {
                "type": "DESERIALIZATION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)

        # 若未能构建完整路径，但同一文件中同时存在 Source 和 DESERIALIZATION Sink，则做降级告警
        if reported_sinks:
            return

        try:
            source_ids: Set[str] = getattr(graph, "_sources", set())
            sink_ids: Set[str] = getattr(graph, "_sinks", set())
        except Exception:
            return

        if not source_ids or not sink_ids:
            return

        # 仅当存在 DESERIALIZATION 类别的 Sink 且至少一个 Source 节点时，视为风险
        for sink_id in sink_ids:
            sink = getattr(graph, "_nodes", {}).get(sink_id)  # type: ignore[attr-defined]
            if sink is None:
                continue
            category = (sink.extras or {}).get("category") if hasattr(sink, "extras") else None
            if category != "deserialization":
                continue

            line_no = getattr(sink, "line", 0) or 0
            details = (
                "检测到 Java 代码中存在 ObjectInputStream.readObject 调用，且同一文件中存在用户输入来源，"
                "建议确认反序列化的数据是否经过严格验证或改用 JSON 等安全格式。"
            )
            finding: Dict[str, Any] = {
                "type": "DESERIALIZATION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
            }
            context.add_finding(finding)
            break


__all__ = ["JavaDeserializationAstRule"]

