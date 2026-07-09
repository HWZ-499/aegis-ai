"""Go SSRF AST rule."""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import is_user_input_node

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


class GoSSRFAstRule(SecurityRule):
    """Detect user-controlled URLs passed to net/http clients."""

    URL_FIRST_ARG_METHODS = frozenset({"Get", "Head"})
    URL_SECOND_ARG_METHODS = frozenset({"Post", "PostForm", "NewRequest", "NewRequestWithContext"})

    def __init__(self) -> None:
        super().__init__(rule_id="SSRF_GO_AST", severity="High", languages=["go"])
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return
        if node.type != "call_expression":
            return

        method_name, receiver_name = self._get_qualified_name(node)
        arguments = self._get_arguments(node)
        if method_name in self.URL_FIRST_ARG_METHODS and arguments:
            if self._is_http_receiver(receiver_name) and self._subtree_has_user_input(arguments[0], context):
                self._report(node, context, f"{receiver_name}.{method_name}")
            return

        if method_name in self.URL_SECOND_ARG_METHODS and len(arguments) >= 2:
            if self._is_http_receiver(receiver_name) and self._subtree_has_user_input(arguments[1], context):
                self._report(node, context, f"{receiver_name}.{method_name}")

    @staticmethod
    def _is_http_receiver(receiver_name: str | None) -> bool:
        if receiver_name is None:
            return False
        normalized = receiver_name.lower()
        return normalized == "http" or "client" in normalized

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        if is_user_input_node(node, context, language="go"):
            return True
        return any(self._subtree_has_user_input(child, context) for child in getattr(node, "children", []))

    def _report(self, node: Any, context: AnalysisContext, sink_name: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "SSRF",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"Go: {sink_name}() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。"
                "建议使用协议和域名白名单，并拒绝环回、内网和云元数据地址。"
            ),
            "cwe": "CWE-918",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _get_qualified_name(node: Any) -> tuple[str | None, str | None]:
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") != "selector_expression":
                continue
            parts: list[str] = []
            for sub in getattr(child, "children", []):
                if getattr(sub, "type", "") in {"identifier", "field_identifier"}:
                    raw = getattr(sub, "text", None)
                    if isinstance(raw, bytes):
                        parts.append(raw.decode("utf-8"))
                    elif isinstance(raw, str):
                        parts.append(raw)
            if len(parts) >= 2:
                return parts[-1], parts[0]
        return None, None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") == "argument_list":
                return [
                    argument
                    for argument in getattr(child, "children", [])
                    if getattr(argument, "type", "") not in {"(", ")", ","}
                ]
        return []


__all__ = ["GoSSRFAstRule"]
