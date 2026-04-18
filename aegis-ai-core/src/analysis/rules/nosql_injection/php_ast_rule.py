"""PHP NoSQL Injection AST rule — Tree-sitter based."""

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


class PhpNoSQLInjectionAstRule(SecurityRule):
    """Detect NoSQL injection in PHP MongoDB calls."""

    MONGO_METHODS = frozenset(
        {
            "find",
            "findOne",
            "findOneAndUpdate",
            "findOneAndDelete",
            "update",
            "updateOne",
            "updateMany",
            "insert",
            "insertOne",
            "insertMany",
            "delete",
            "deleteOne",
            "deleteMany",
            "remove",
            "count",
            "aggregate",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="NOSQL_INJECTION_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        if node.type != "member_call_expression":
            return

        method_name = self._get_method_name(node)
        if not method_name or method_name not in self.MONGO_METHODS:
            return

        line = node.start_point[0] + 1
        if line in self._reported:
            return

        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        if _subtree_contains_php_user_input(arg, context):
                            self._reported.add(line)
                            finding = {
                                "type": "NOSQL_INJECTION",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": f"PHP: $collection->{method_name}() 的参数包含用户输入，存在 NoSQL 注入风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return
                        # Only check first argument
                        break

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "name":
                return child.text.decode("utf-8") if hasattr(child, "text") else None
        return None


__all__ = ["PhpNoSQLInjectionAstRule"]
