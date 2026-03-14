"""PHP Path Traversal AST rule — Tree-sitter based."""

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


class PhpPathTraversalAstRule(SecurityRule):
    """Detect path traversal via file operations with user input."""

    FILE_FUNCS = frozenset(
        {
            "file_get_contents",
            "file_put_contents",
            "readfile",
            "fopen",
            "file",
            "unlink",
            "copy",
            "rename",
            "mkdir",
            "rmdir",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="PATH_TRAVERSAL_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        # include/require expressions
        if node.type == "include_expression":
            self._check_include(node, context)
        # function_call_expression: file_get_contents(), fopen(), readfile()
        elif node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name and func_name in self.FILE_FUNCS:
                self._check_file_func(node, context, func_name)

    def _check_include(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        # include expression children: "include" keyword + the path expression
        for child in node.children:
            if child.type in ("include", "include_once", "require", "require_once", ";"):
                continue
            if _subtree_contains_php_user_input(child, context):
                self._reported.add(line)
                finding = {
                    "type": "PATH_TRAVERSAL",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line,
                    "details": "PHP: include/require 的路径包含用户输入，存在路径遍历/文件包含风险。",
                }
                finding.update(tree_sitter_node_to_range(node))
                context.add_finding(finding)
                return
            if child.type == "variable_name":
                var = self._text(child).lstrip("$")
                if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                    self._reported.add(line)
                    finding = {
                        "type": "PATH_TRAVERSAL",
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "line": line,
                        "details": f"PHP: include/require 的路径变量 ${var} 被污染，存在路径遍历风险。",
                    }
                    finding.update(tree_sitter_node_to_range(node))
                    context.add_finding(finding)
                    return

    def _check_file_func(self, node: Any, context: AnalysisContext, func: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        for child in node.children:
            if child.type == "arguments":
                # Check first argument (the file path)
                for arg in child.children:
                    if arg.type == "argument":
                        if _subtree_contains_php_user_input(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "PATH_TRAVERSAL",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": f"PHP: {func}() 的路径参数包含用户输入，存在路径遍历风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return
                        inner = self._unwrap(arg)
                        if inner.type == "variable_name":
                            var = self._text(inner).lstrip("$")
                            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                                self._reported.add(line)
                                finding = {
                                    "type": "PATH_TRAVERSAL",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": f"PHP: {func}() 的路径变量 ${var} 被污染，存在路径遍历风险。",
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return
                        # Only check first argument
                        break

    @staticmethod
    def _unwrap(arg: Any) -> Any:
        if arg.type == "argument":
            for c in arg.children:
                if c.type not in (",", "(", ")"):
                    return c
        return arg

    @staticmethod
    def _get_func_name(node: Any) -> str | None:
        for c in node.children:
            if c.type == "name":
                return c.text.decode("utf-8") if hasattr(c, "text") else None
        return None

    @staticmethod
    def _text(node: Any) -> str:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return ""


__all__ = ["PhpPathTraversalAstRule"]
