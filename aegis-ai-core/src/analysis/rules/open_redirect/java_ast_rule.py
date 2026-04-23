"""
open_redirect.java_ast_rule

Java Open Redirect AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - response.sendRedirect(userInput)
   - response.setHeader("Location", userInput)
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

# 重定向方法（sink）
_REDIRECT_METHODS = frozenset(["sendRedirect"])

# setHeader 中的重定向 header 名
_REDIRECT_HEADERS = frozenset(["location", "refresh"])

# Java 用户输入方法（用于 method_invocation 边界匹配）
_JAVA_USER_INPUT_METHODS = frozenset(
    [
        "getParameter",
        "getParameterValues",
        "getHeader",
        "getCookies",
        "getInputStream",
        "getReader",
        "getQueryString",
        "getRequestURI",
        "getPathInfo",
        "getBody",
    ]
)


class JavaOpenRedirectAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Java Open Redirect 检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="OPEN_REDIRECT_JAVA_TAINT",
            severity="Medium",
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

    def _check_method_invocation(self, node: Any, context: AnalysisContext) -> None:
        method_name = self._get_method_name(node)
        if method_name is None:
            return

        # Case 1: response.sendRedirect(userInput)
        if method_name in _REDIRECT_METHODS:
            full_text = self._get_node_text(node) or ""
            full_lower = full_text.lower()
            if "response" not in full_lower and "resp" not in full_lower:
                return
            args = self._get_arguments(node)
            if not args:
                return
            if self._subtree_has_user_input(args[0], context):
                self._report(node, context, "sendRedirect")
            return

        # Case 2: response.setHeader("Location", userInput)
        if method_name == "setHeader":
            full_text = self._get_node_text(node) or ""
            full_lower = full_text.lower()
            if "response" not in full_lower and "resp" not in full_lower:
                return
            args = self._get_arguments(node)
            if len(args) < 2:
                return
            header_name = self._get_node_text(args[0]) or ""
            if header_name.strip('"').strip("'").lower() not in _REDIRECT_HEADERS:
                return
            if self._subtree_has_user_input(args[1], context):
                self._report(node, context, "setHeader('Location', ...)")
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
            if category != "open_redirect":
                continue
            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue
            reported_sinks.add(sink_id)
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")
            finding: dict[str, Any] = {
                "type": "OPEN_REDIRECT",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Java 代码中用户可控输入直接用于构造重定向目标，"
                    "可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。"
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
        if getattr(node, "type", "") == "method_invocation":
            if self._is_java_user_input_call(node):
                return True
            # method_invocation 下避免把 receiver 标识符（如 request）直接当作用户输入；
            # 仅递归参数列表，降低 request.getAttribute(...) 等误报风险。
            for arg in self._get_arguments(node):
                if self._subtree_has_user_input(arg, context):
                    return True
            return False

        if is_user_input_node(node, context, language="java"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _is_java_user_input_call(self, node: Any) -> bool:
        receiver = self._get_receiver_name(node)
        method_name = self._get_method_name(node)
        if receiver not in ("request", "req") or method_name is None:
            return False
        return method_name in _JAVA_USER_INPUT_METHODS

    def _report(self, node: Any, context: AnalysisContext, method_name: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "OPEN_REDIRECT",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {method_name}() 调用中包含用户可控输入，"
                "可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["JavaOpenRedirectAstRule"]
