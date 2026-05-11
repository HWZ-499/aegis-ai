"""PHP Deserialization AST rule — Tree-sitter based."""

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


class PhpDeserializationAstRule(SecurityRule):
    """Detect unsafe unserialize() with user input."""

    def __init__(self) -> None:
        super().__init__(rule_id="DESERIALIZATION_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        if node.type != "function_call_expression":
            return

        func_name = self._get_func_name(node)
        if func_name != "unserialize":
            return

        line = node.start_point[0] + 1
        if line in self._reported:
            return

        # Check if allowed_classes option is set (second argument)
        args = self._get_args(node)
        if len(args) >= 2:
            second_text = self._text(args[1]).lower()
            if "allowed_classes" in second_text and self._allowed_classes_is_restrictive(second_text):
                return  # Restricted to false or a concrete allowlist.

        # Check first argument for user input
        if args:
            first_arg = args[0]
            if _subtree_contains_php_user_input(first_arg, context):
                self._report(node, context, line)
                return
            inner = self._unwrap(first_arg)
            if inner.type == "variable_name":
                var = self._text(inner).lstrip("$")
                if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                    self._report(node, context, line)
                    return

    def _report(self, node: Any, context: AnalysisContext, line: int) -> None:
        self._reported.add(line)
        finding = {
            "type": "DESERIALIZATION",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": "PHP: unserialize() 参数来自用户输入且未限制 allowed_classes，存在反序列化风险。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _get_args(node: Any) -> list[Any]:
        for child in node.children:
            if child.type == "arguments":
                return [c for c in child.children if c.type == "argument"]
        return []

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

    @staticmethod
    def _allowed_classes_is_restrictive(option_text: str) -> bool:
        """allowed_classes=true is unsafe; false or an explicit array is restrictive."""
        compact = option_text.replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "")
        if "allowed_classes" not in compact:
            return False
        if "allowed_classes'=>true" in compact or '"allowed_classes"=>true' in compact:
            return False
        if "allowed_classes'=>1" in compact or '"allowed_classes"=>1' in compact:
            return False
        if "allowed_classes'=>false" in compact or '"allowed_classes"=>false' in compact:
            return True
        if "allowed_classes'=>[" in compact or '"allowed_classes"=>[' in compact:
            return True
        if "allowed_classes'=>array(" in compact or '"allowed_classes"=>array(' in compact:
            return True
        return False


__all__ = ["PhpDeserializationAstRule"]
