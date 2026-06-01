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
_SCRIPT_ENGINE_RECEIVERS = frozenset(["ScriptEngine", "Nashorn", "NashornScriptEngine"])


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
        self._receiver_types: dict[str, str] = {}

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()
        self._receiver_types = {}

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type in ("formal_parameter", "local_variable_declaration", "field_declaration"):
            self._track_declared_receiver_type(node)
        elif node.type == "method_invocation":
            self._check_method_invocation(node, context)
        elif node.type == "object_creation_expression":
            self._check_process_builder(node, context)

    def _check_method_invocation(self, node: Any, context: AnalysisContext) -> None:
        """检测 Runtime.getRuntime().exec(var), ScriptEngine.eval(var) 等。"""
        method_name = self._get_method_name(node)
        if method_name not in _RCE_METHODS:
            return

        if not self._has_dangerous_receiver(node, method_name):
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
        method_index = JavaRCEAstRule._get_method_identifier_index(node)
        if method_index is None:
            return None
        child = node.children[method_index]
        text = child.text
        return text.decode("utf-8") if isinstance(text, bytes) else str(text)

    @staticmethod
    def _get_method_identifier_index(node: Any) -> int | None:
        children = list(getattr(node, "children", []) or [])
        argument_index = next(
            (index for index, child in enumerate(children) if child.type == "argument_list"),
            len(children),
        )
        for index in range(argument_index - 1, -1, -1):
            if children[index].type == "identifier":
                return index
        return None

    @staticmethod
    def _get_receiver_node(node: Any) -> Any | None:
        children = list(getattr(node, "children", []) or [])
        method_index = JavaRCEAstRule._get_method_identifier_index(node)
        if method_index is None:
            return None

        index = method_index - 1
        while index >= 0 and children[index].type in (".", "::"):
            index -= 1
        if index < 0:
            return None
        return children[index]

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

    def _track_declared_receiver_type(self, node: Any) -> None:
        type_name = self._extract_declared_type(node)
        if not type_name:
            return

        for child in getattr(node, "children", []) or []:
            if child.type == "identifier":
                name = self._get_node_text(child)
                if name:
                    self._receiver_types[name] = type_name
            elif child.type == "variable_declarator":
                var_name = self._extract_variable_declarator_name(child)
                if var_name:
                    self._receiver_types[var_name] = type_name

    def _has_dangerous_receiver(self, node: Any, method_name: str) -> bool:
        receiver = self._get_receiver_node(node)
        receiver_type = self._resolve_receiver_type(receiver)

        if method_name == "exec":
            return receiver_type == "Runtime"
        if method_name == "start":
            return receiver_type == "ProcessBuilder"
        if method_name == "eval":
            return receiver_type in _SCRIPT_ENGINE_RECEIVERS
        if method_name == "loadLibrary":
            return receiver_type == "System"
        return False

    def _resolve_receiver_type(self, receiver: Any | None) -> str | None:
        if receiver is None:
            return None

        receiver_text = (self._get_node_text(receiver) or "").strip()
        if not receiver_text:
            return None

        simple_receiver = self._simple_type_name(receiver_text)
        if simple_receiver in _RCE_RECEIVERS:
            return simple_receiver
        if receiver_text.endswith("Runtime.getRuntime()"):
            return "Runtime"

        if receiver.type == "object_creation_expression":
            return self._extract_created_type(receiver)

        if receiver.type == "method_invocation" and receiver_text.endswith("Runtime.getRuntime()"):
            return "Runtime"

        receiver_name = receiver_text.rsplit(".", 1)[-1]
        return self._receiver_types.get(receiver_text) or self._receiver_types.get(receiver_name)

    def _extract_declared_type(self, node: Any) -> str | None:
        for child in getattr(node, "children", []) or []:
            if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                return self._simple_type_name(self._get_node_text(child) or "")
        return None

    def _extract_created_type(self, node: Any) -> str | None:
        for child in getattr(node, "children", []) or []:
            if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                return self._simple_type_name(self._get_node_text(child) or "")
        return None

    def _extract_variable_declarator_name(self, node: Any) -> str | None:
        for child in getattr(node, "children", []) or []:
            if child.type == "identifier":
                return self._get_node_text(child)
        return None

    @staticmethod
    def _simple_type_name(type_text: str) -> str:
        clean = type_text.strip()
        if "<" in clean:
            clean = clean.split("<", 1)[0]
        clean = clean.replace("[]", "").strip()
        return clean.rsplit(".", 1)[-1]

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
