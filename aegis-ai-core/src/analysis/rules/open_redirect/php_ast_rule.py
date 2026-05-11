"""PHP Open Redirect AST rule — Tree-sitter based."""

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


class PhpOpenRedirectAstRule(SecurityRule):
    """Detect open redirect via header('Location: ...') with user input."""

    def __init__(self) -> None:
        super().__init__(rule_id="OPEN_REDIRECT_PHP_AST", severity="Medium", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        if node.type != "function_call_expression":
            return

        func_name = self._get_func_name(node)
        if func_name != "header":
            return

        line = node.start_point[0] + 1
        if line in self._reported:
            return

        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        arg_text = self._text(arg).lower()
                        if not self._arg_represents_location_header(arg, context, line):
                            continue
                        if _subtree_contains_php_user_input(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "OPEN_REDIRECT",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": "PHP: header('Location: ...') 的重定向目标包含用户输入，存在开放重定向风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return
                        # Check tainted variables in the argument
                        if self._arg_has_tainted_var(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "OPEN_REDIRECT",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": "PHP: header('Location: ...') 的重定向目标包含污染变量，存在开放重定向风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return

    def _arg_represents_location_header(self, node: Any, context: AnalysisContext, sink_line: int) -> bool:
        text = self._text(node).lower()
        if "location" in text:
            return True
        inner = self._unwrap(node)
        if getattr(inner, "type", "") != "variable_name":
            return False
        var = self._text(inner).lstrip("$")
        assignment = self._find_latest_assignment_expr(var, sink_line, context)
        return assignment is not None and "location" in assignment.lower()

    def _arg_has_tainted_var(self, node: Any, context: AnalysisContext) -> bool:
        if node.type == "variable_name":
            var = self._text(node).lstrip("$")
            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                return True
        if hasattr(node, "children"):
            for child in node.children:
                if self._arg_has_tainted_var(child, context):
                    return True
        return False

    @staticmethod
    def _unwrap(arg: Any) -> Any:
        if arg.type == "argument":
            for child in arg.children:
                if child.type not in (",", "(", ")"):
                    return child
        return arg

    @staticmethod
    def _find_latest_assignment_expr(var_name: str, sink_line: int, context: AnalysisContext) -> str | None:
        source = context.extras.get("source")
        if not isinstance(source, str) or not source:
            return None

        import re

        lines = source.splitlines()
        upper_bound = min(max(sink_line - 1, 0), len(lines))
        assign_re = re.compile(rf"\${re.escape(var_name)}\s*=\s*(.+?)\s*;?\s*$")
        for idx in range(upper_bound - 1, -1, -1):
            matched = assign_re.search(lines[idx])
            if matched is not None:
                return matched.group(1).strip()
        return None

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


__all__ = ["PhpOpenRedirectAstRule"]
