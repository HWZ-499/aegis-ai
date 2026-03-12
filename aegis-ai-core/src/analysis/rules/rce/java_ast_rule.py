"""
rce.java_ast_rule

Java RCE / 命令执行 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - Runtime.getRuntime().exec(userInput)
   - new ProcessBuilder(userInput).start()
   - ScriptEngine.eval(userInput)
2. TaintGraph 路径分析（after_file，兜底）。
"""

from __future__ import annotations

from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    safe_find_paths,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]

# 危险的命令执行方法
_RCE_METHODS = frozenset(["exec", "start", "eval", "loadLibrary"])

# 危险的类/对象
_RCE_RECEIVERS = frozenset(["Runtime", "ProcessBuilder", "ScriptEngine", "Nashorn", "System"])


class JavaRCEAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Java RCE 检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RCE_COMMAND_EXEC_JAVA_TAINT",
            severity="Critical",
            languages=["java"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "method_invocation":
            self._check_method_invocation(node, context)
        elif node.type == "object_creation_expression":
            self._check_process_builder(node, context)

    def _check_method_invocation(self, node: Any, context: AnalysisContext) -> None:
        """检测 Runtime.getRuntime().exec(var), ScriptEngine.eval(var) 等。"""
        method_name = self._get_method_name(node)
        if method_name not in _RCE_METHODS:
            return

        # 检查参数中是否有用户输入
        args = self._get_arguments(node)
        if not args:
            return

        for arg in args:
            if self._subtree_has_user_input(arg, context):
                self._report(node, context, method_name)
                return

    def _check_process_builder(self, node: Any, context: AnalysisContext) -> None:
        """检测 new ProcessBuilder(userInput)。"""
        # 找到类名
        class_name = None
        for child in node.children:
            if child.type == "type_identifier":
                class_name = self._get_node_text(child)
                break

        if class_name != "ProcessBuilder":
            return

        args = self._get_arguments(node)
        for arg in args:
            if self._subtree_has_user_input(arg, context):
                self._report(node, context, "new ProcessBuilder")
                return

    def after_file(self, context: AnalysisContext) -> None:
        """TaintGraph 兜底。"""
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
            if category != "rce":
                continue
            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue
            reported_sinks.add(sink_id)
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")
            finding: dict[str, Any] = {
                "type": "RCE_COMMAND_EXEC",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Java 代码中用户可控输入流入命令执行点，"
                    "存在命令注入风险，建议使用固定命令白名单或严格转义参数。"
                ),
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "identifier":
                text = child.text
                return text.decode("utf-8") if isinstance(text, bytes) else str(text)
        return None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        if is_user_input_node(node, context, language="java"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _report(self, node: Any, context: AnalysisContext, method_name: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "RCE_COMMAND_EXEC",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {method_name}() 调用中包含用户可控输入，"
                "存在命令注入风险，建议使用固定命令白名单或严格校验参数。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["JavaRCEAstRule"]
