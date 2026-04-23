"""
deserialization.java_ast_rule

Java 反序列化风险 AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - ObjectInputStream.readObject() / readUnshared()
   - XMLDecoder.readObject()
   - Yaml.load(userInput) (SnakeYAML — 检查参数是否用户输入)
   - ObjectMapper.readValue(userInput, ...) (Jackson — 仅当第一个参数用户可控)
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

# 无条件危险的反序列化方法（receiver 匹配即报告，无需检查参数）
_UNCONDITIONAL_METHODS = frozenset(["readObject", "readUnshared"])

# 需要检查第一个参数是否用户可控的方法
_CONDITIONAL_METHODS = frozenset(["load", "readValue"])

# readObject / readUnshared 的合法 receiver（不区分大小写匹配）
_DANGEROUS_RECEIVERS = frozenset(
    [
        "objectinputstream",
        "xmldecoder",
        "ois",
        "decoder",
    ]
)

# load / readValue 的 receiver 关键词（不区分大小写匹配）
_CONDITIONAL_RECEIVERS: dict[str, frozenset[str]] = {
    "load": frozenset(["yaml"]),
    "readValue": frozenset(["objectmapper", "mapper"]),
}

# 反序列化安全措施（sanitizer 关键词）
_SANITIZERS = frozenset(
    [
        "ObjectInputFilter",
        "ValidatingObjectInputStream",
        "SerialKiller",
        "setObjectInputFilter",
        "lookAheadObjectInputStream",
        "safeObjectInputStream",
    ]
)


class JavaDeserializationAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Java 反序列化风险检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="DESERIALIZATION_JAVA_TAINT",
            severity="High",
            languages=["java"],
        )
        self._reported_lines: set[int] = set()
        self._var_assignments: dict[str, Any] = {}

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()
        self._var_assignments = {}

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "local_variable_declaration":
            self._track_local_variable_declaration(node)
        elif node.type == "resource":
            self._track_resource_assignment(node)
        elif node.type == "assignment_expression":
            self._track_assignment_expression(node)

        if node.type == "method_invocation":
            self._check_method_invocation(node, context)

    # ------------------------------------------------------------------
    # visit 阶段检测逻辑
    # ------------------------------------------------------------------

    def _check_method_invocation(self, node: Any, context: AnalysisContext) -> None:
        """分发反序列化 API 调用检测。"""
        method_name = self._get_method_name(node)
        if method_name is None:
            return

        # Case 1: ObjectInputStream.readObject()/readUnshared(), XMLDecoder.readObject()
        if method_name in _UNCONDITIONAL_METHODS:
            self._check_unconditional_sink(node, context, method_name)
            return

        # Case 2: Yaml.load(userInput), ObjectMapper.readValue(userInput, ...)
        if method_name in _CONDITIONAL_METHODS:
            self._check_conditional_sink(node, context, method_name)
            return

    def _check_unconditional_sink(
        self,
        node: Any,
        context: AnalysisContext,
        method_name: str,
    ) -> None:
        """检测 ObjectInputStream.readObject() 等无条件危险方法。"""
        receiver = self._get_receiver_name(node)
        if receiver is None:
            return

        # 确认 receiver 是已知的危险类型（变量名或赋值表达式）
        if not self._is_dangerous_receiver(node, receiver):
            return

        # 检查是否存在安全过滤措施
        if self._receiver_has_sanitizer(receiver):
            return

        # 仅在可判定为不可信输入上下文时报告，降低本地安全数据样例误报
        if not self._receiver_from_untrusted_source(receiver, context):
            return

        self._report(node, context, method_name)

    def _check_conditional_sink(
        self,
        node: Any,
        context: AnalysisContext,
        method_name: str,
    ) -> None:
        """检测 Yaml.load(userInput), ObjectMapper.readValue(userInput, ...) 等。"""
        full_text = self._get_node_text(node) or ""
        full_lower = full_text.lower()

        # 确认 receiver 匹配预期的类/对象
        expected_receivers = _CONDITIONAL_RECEIVERS.get(method_name)
        if expected_receivers is None:
            return

        if not any(recv in full_lower for recv in expected_receivers):
            return

        # 检查第一个参数是否是用户输入
        args = self._get_arguments(node)
        if not args:
            return

        first_arg = args[0]
        if not self._subtree_has_user_input(first_arg, context):
            return

        # Sanitizer 感知：如果所有标识符均已被净化，跳过
        identifiers = self._collect_identifiers(first_arg)
        if identifiers and (context.taint_graph or context.dataflow_tracker):
            if all(context.is_var_sanitized(v) for v in identifiers):
                return

        self._report(node, context, method_name)

    # ------------------------------------------------------------------
    # after_file: TaintGraph 兜底（两阶段：完整路径 + 降级告警）
    # ------------------------------------------------------------------

    def after_file(self, context: AnalysisContext) -> None:
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: set[str] = set()

        # 优先使用完整污点路径（若存在）
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
            if category != "deserialization":
                continue

            line_no = getattr(sink, "line", 0) or 0
            # 跳过 visit 阶段已报告的行
            if line_no in self._reported_lines:
                continue

            reported_sinks.add(sink_id)

            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")

            details = (
                "检测到 Java 代码中对不可信数据执行反序列化（如 ObjectInputStream.readObject），"
                "可能导致任意代码执行或敏感对象加载，建议改用安全数据格式（JSON）或加入类型白名单校验。"
            )

            finding: dict[str, Any] = {
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
        if reported_sinks or self._reported_lines:
            return

        source_ids: set[str] = getattr(graph, "_sources", set())
        sink_ids: set[str] = getattr(graph, "_sinks", set())

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
            fallback_finding: dict[str, Any] = {
                "type": "DESERIALIZATION",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": details,
            }
            context.add_finding(fallback_finding)
            break

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
        identifiers = [child for child in node.children if getattr(child, "type", "") == "identifier"]
        if not identifiers:
            return None
        text = identifiers[-1].text
        return text.decode("utf-8") if isinstance(text, bytes) else str(text)

    @staticmethod
    def _get_receiver_name(node: Any) -> str | None:
        children = list(node.children)
        if len(children) >= 3 and children[1].type == "." and children[0].type == "identifier":
            text = children[0].text
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

    def _collect_identifiers(self, node: Any) -> list[str]:
        result: list[str] = []
        if node.type == "identifier":
            text = self._get_node_text(node)
            if text:
                result.append(text)
        for child in getattr(node, "children", []) or []:
            result.extend(self._collect_identifiers(child))
        return result

    def _is_dangerous_receiver(self, node: Any, receiver: str) -> bool:
        receiver_lower = receiver.lower()
        if receiver_lower in _DANGEROUS_RECEIVERS:
            return True

        full_lower = (self._get_node_text(node) or "").lower()
        if any(recv in full_lower for recv in _DANGEROUS_RECEIVERS):
            return True

        assigned_expr = self._resolve_var_expr(receiver, set())
        if assigned_expr is None:
            return False
        assigned_lower = (self._get_node_text(assigned_expr) or "").lower()
        return "objectinputstream" in assigned_lower or "xmldecoder" in assigned_lower

    def _receiver_has_sanitizer(self, receiver: str) -> bool:
        assigned_expr = self._resolve_var_expr(receiver, set())
        if assigned_expr is None:
            return False
        assigned_text = self._get_node_text(assigned_expr) or ""
        return any(s in assigned_text for s in _SANITIZERS)

    def _receiver_from_untrusted_source(self, receiver: str, context: AnalysisContext) -> bool:
        assigned_expr = self._resolve_var_expr(receiver, set())
        if assigned_expr is None:
            return self._file_has_java_user_input(context)

        assigned_text = self._get_node_text(assigned_expr) or ""
        assigned_lower = assigned_text.lower()

        if "bytearrayinputstream" in assigned_lower:
            # ByteArrayInputStream 仅在文件中存在明确用户输入来源时视为风险
            return self._file_has_java_user_input(context)

        if "getinputstream(" in assigned_lower:
            return True

        if "socket" in assigned_lower and "inputstream" in assigned_lower:
            return True

        return self._subtree_has_user_input(assigned_expr, context)

    @staticmethod
    def _file_has_java_user_input(context: AnalysisContext) -> bool:
        source_code = context.extras.get("source") or ""
        if not source_code:
            return False
        patterns = (
            "request.getParameter(",
            "req.getParameter(",
            "request.getHeader(",
            "request.getInputStream(",
            "request.getReader(",
            "request.getQueryString(",
            "request.getRequestURI(",
            "request.getPathInfo(",
            "request.getBody(",
        )
        source_lower = source_code.lower()
        return any(p.lower() in source_lower for p in patterns)

    def _track_local_variable_declaration(self, node: Any) -> None:
        for child in getattr(node, "children", []) or []:
            if getattr(child, "type", "") == "variable_declarator":
                self._track_declarator(child)

    def _track_resource_assignment(self, node: Any) -> None:
        var_name: str | None = None
        expr_node: Any | None = None
        seen_equal = False

        for child in getattr(node, "children", []) or []:
            ctype = getattr(child, "type", "")
            if ctype == "identifier" and var_name is None:
                var_name = self._get_node_text(child) or None
                continue
            if ctype == "=":
                seen_equal = True
                continue
            if seen_equal:
                expr_node = child
                break

        if var_name and expr_node is not None:
            self._var_assignments[var_name] = expr_node

    def _track_declarator(self, declarator: Any) -> None:
        var_name: str | None = None
        expr_node: Any | None = None
        seen_equal = False

        for child in getattr(declarator, "children", []) or []:
            ctype = getattr(child, "type", "")
            if ctype == "identifier" and var_name is None:
                var_name = self._get_node_text(child) or None
                continue
            if ctype == "=":
                seen_equal = True
                continue
            if seen_equal:
                expr_node = child
                break

        if var_name and expr_node is not None:
            self._var_assignments[var_name] = expr_node

    def _track_assignment_expression(self, node: Any) -> None:
        left_node: Any | None = None
        right_node: Any | None = None
        seen_equal = False

        for child in getattr(node, "children", []) or []:
            ctype = getattr(child, "type", "")
            if ctype == "=":
                seen_equal = True
                continue
            if not seen_equal and ctype == "identifier":
                left_node = child
                continue
            if seen_equal:
                right_node = child
                break

        if left_node is None or right_node is None:
            return

        name = self._get_node_text(left_node) or ""
        if not name:
            return
        self._var_assignments[name] = right_node

    def _resolve_var_expr(self, var_name: str, seen_vars: set[str]) -> Any | None:
        if var_name in seen_vars:
            return None
        seen_vars.add(var_name)

        expr = self._var_assignments.get(var_name)
        if expr is None:
            return None

        if getattr(expr, "type", "") == "identifier":
            nested_name = self._get_node_text(expr) or ""
            if nested_name:
                nested = self._resolve_var_expr(nested_name, seen_vars)
                if nested is not None:
                    return nested

        return expr

    def _report(self, node: Any, context: AnalysisContext, method_name: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "DESERIALIZATION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {method_name}() 调用中存在不安全的反序列化操作，"
                "可能导致任意代码执行，建议改用安全数据格式或加入类型白名单校验。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["JavaDeserializationAstRule"]
