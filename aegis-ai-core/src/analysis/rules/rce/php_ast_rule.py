"""PHP RCE (Remote Code Execution) AST rule — Tree-sitter based."""

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


class PhpRCEAstRule(SecurityRule):
    """Detect command execution with user input in PHP."""

    DANGEROUS_FUNCS = frozenset(
        {
            "system",
            "exec",
            "passthru",
            "shell_exec",
            "popen",
            "proc_open",
            "pcntl_exec",
            "eval",
            "assert",
            "preg_replace",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="RCE_PHP_AST", severity="Critical", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        if node.type != "function_call_expression":
            return

        func_name = self._get_func_name(node)
        if not func_name or func_name not in self.DANGEROUS_FUNCS:
            return

        line = node.start_point[0] + 1
        if line in self._reported:
            return

        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        inner = self._unwrap(arg)
                        # Skip string literals (no user input)
                        if inner.type in ("string", "encapsed_string"):
                            if not self._has_variable(inner):
                                continue
                        if _subtree_contains_php_user_input(arg, context):
                            self._report(node, context, line, func_name)
                            return
                        # Check tainted variable
                        if inner.type == "variable_name":
                            var = self._text(inner).lstrip("$")
                            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                                self._report(node, context, line, func_name)
                                return

    def _report(self, node: Any, context: AnalysisContext, line: int, func: str) -> None:
        self._reported.add(line)
        finding = {
            "type": "RCE_COMMAND_EXEC",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": f"PHP: {func}() 参数来自用户输入，存在远程代码/命令执行风险。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _unwrap(arg: Any) -> Any:
        if arg.type == "argument":
            for c in arg.children:
                if c.type not in (",", "(", ")"):
                    return c
        return arg

    @staticmethod
    def _has_variable(node: Any) -> bool:
        if hasattr(node, "children"):
            for c in node.children:
                if c.type == "variable_name":
                    return True
        return False

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


__all__ = ["PhpRCEAstRule"]
