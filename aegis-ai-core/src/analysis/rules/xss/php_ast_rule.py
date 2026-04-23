"""PHP XSS AST rule — Tree-sitter based."""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import _subtree_contains_php_user_input

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any  # type: ignore[misc,assignment]


class PhpXSSAstRule(SecurityRule):
    """Detect XSS (unescaped output) in PHP."""

    SANITIZERS = frozenset({"htmlspecialchars", "htmlentities", "strip_tags"})

    def __init__(self) -> None:
        super().__init__(rule_id="XSS_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        # echo_statement: echo $name;
        if node.type == "echo_statement":
            self._check_echo(node, context)
        # function_call_expression: print($name)
        elif node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name in ("print", "printf", "vprintf"):
                self._check_print(node, context, func_name)

    def _check_echo(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        for child in node.children:
            if child.type in ("echo",):
                continue
            if child.type == ";":
                continue
            # Check if the echoed expression is wrapped in a sanitizer
            if child.type == "function_call_expression":
                fn = self._get_func_name(child)
                if fn and fn in self.SANITIZERS:
                    return
            if _subtree_contains_php_user_input(child, context):
                self._reported.add(line)
                finding = {
                    "type": "XSS_RISK",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line,
                    "details": "PHP: echo 输出包含用户输入且未经 htmlspecialchars 转义，存在 XSS 风险。",
                }
                finding.update(tree_sitter_node_to_range(node))
                context.add_finding(finding)
                return
            # Tainted variable
            if child.type == "variable_name":
                var = self._text(child).lstrip("$")
                if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                    self._reported.add(line)
                    finding = {
                        "type": "XSS_RISK",
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "line": line,
                        "details": f"PHP: echo 输出变量 ${var} 被污染且未转义，存在 XSS 风险。",
                    }
                    finding.update(tree_sitter_node_to_range(node))
                    context.add_finding(finding)
                    return

    def _check_print(self, node: Any, context: AnalysisContext, func: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        # Skip sanitizer-wrapped
                        inner = self._unwrap(arg)
                        if inner.type == "function_call_expression":
                            fn = self._get_func_name(inner)
                            if fn and fn in self.SANITIZERS:
                                return
                        if _subtree_contains_php_user_input(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "XSS_RISK",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": f"PHP: {func}() 输出包含用户输入且未转义，存在 XSS 风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return

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


__all__ = ["PhpXSSAstRule"]
