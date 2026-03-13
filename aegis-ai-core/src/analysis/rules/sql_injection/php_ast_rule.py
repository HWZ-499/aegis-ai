"""PHP SQL Injection AST rule — Tree-sitter based."""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import _subtree_contains_php_user_input

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any


class PhpSQLInjectionAstRule(SecurityRule):
    """Detect SQL injection in PHP via Tree-sitter AST."""

    QUERY_METHODS = frozenset({
        "query", "exec", "execute", "multi_query",
        "pg_query", "pg_query_params",
        "sqlite_query", "querySingle",
    })
    QUERY_FUNCTIONS = frozenset({
        "mysql_query", "mysqli_query", "pg_query", "sqlite_query",
    })

    def __init__(self) -> None:
        super().__init__(rule_id="SQL_INJECTION_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        # member_call_expression: $conn->query($sql)
        if node.type == "member_call_expression":
            method_name = self._get_method_name(node)
            if method_name and method_name in self.QUERY_METHODS:
                # Skip if this is prepare() — parameterized query
                if method_name == "prepare":
                    return
                self._check_args(node, context, f"$obj->{method_name}")

        # function_call_expression: mysql_query($sql)
        elif node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name and func_name in self.QUERY_FUNCTIONS:
                self._check_args(node, context, func_name)

    def _check_args(self, node: Any, context: AnalysisContext, call_desc: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        # Skip simple string literals (no interpolation)
                        inner = self._unwrap_arg(arg)
                        if inner is None:
                            continue
                        if inner.type == "string" and not self._string_has_variable(inner):
                            continue
                        if _subtree_contains_php_user_input(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "SQL_INJECTION",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": f"PHP: {call_desc}() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return
                        # Check tainted variables
                        if inner.type == "variable_name":
                            var = self._get_node_text(inner).lstrip("$")
                            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                                self._reported.add(line)
                                finding = {
                                    "type": "SQL_INJECTION",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": f"PHP: {call_desc}() 的参数变量 ${var} 被污染，存在 SQL 注入风险。",
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return
                        # Concatenated or interpolated strings with tainted vars
                        if inner.type in ("binary_expression", "encapsed_string"):
                            if self._expr_contains_tainted_var(inner, context):
                                self._reported.add(line)
                                finding = {
                                    "type": "SQL_INJECTION",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": f"PHP: {call_desc}() 的参数包含拼接/插值的污染变量，存在 SQL 注入风险。",
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return

    def _expr_contains_tainted_var(self, node: Any, context: AnalysisContext) -> bool:
        if node.type == "variable_name":
            var = self._get_node_text(node).lstrip("$")
            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                return True
        if hasattr(node, "children"):
            for child in node.children:
                if self._expr_contains_tainted_var(child, context):
                    return True
        return False

    @staticmethod
    def _unwrap_arg(arg_node: Any) -> Any:
        if arg_node.type == "argument":
            for c in arg_node.children:
                if c.type not in (",", "(", ")"):
                    return c
        return arg_node

    @staticmethod
    def _string_has_variable(node: Any) -> bool:
        if hasattr(node, "children"):
            for c in node.children:
                if c.type == "variable_name":
                    return True
        return False

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "name":
                return child.text.decode("utf-8") if hasattr(child, "text") else None
        return None

    @staticmethod
    def _get_func_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "name":
                return child.text.decode("utf-8") if hasattr(child, "text") else None
        return None

    @staticmethod
    def _get_node_text(node: Any) -> str:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return ""


__all__ = ["PhpSQLInjectionAstRule"]
