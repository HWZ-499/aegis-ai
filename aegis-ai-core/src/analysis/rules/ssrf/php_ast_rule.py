"""PHP SSRF AST rule."""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import _subtree_contains_php_user_input

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


class PhpSSRFAstRule(SecurityRule):
    """Detect user-controlled URLs passed to PHP server-side request APIs."""

    URL_FIRST_ARG_FUNCS = frozenset(
        {
            "curl_init",
            "file_get_contents",
            "fopen",
            "get_headers",
            "readfile",
            "simplexml_load_file",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="SSRF_PHP_AST", severity="High", languages=["php"])
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return
        if node.type != "function_call_expression":
            return

        function_name = self._get_function_name(node)
        arguments = self._get_arguments(node)
        if function_name in self.URL_FIRST_ARG_FUNCS and arguments:
            if self._has_user_input(arguments[0], context):
                self._report(node, context, function_name)
            return

        if function_name == "curl_setopt" and len(arguments) >= 3:
            option = self._text(arguments[1]).upper()
            if "CURLOPT_URL" in option and self._has_user_input(arguments[2], context):
                self._report(node, context, "curl_setopt(CURLOPT_URL)")

    def _has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        return bool(_subtree_contains_php_user_input(node, context))

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
                f"PHP: {sink_name}() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。"
                "建议限制 URL 协议和域名，并阻止访问环回、内网和云元数据地址。"
            ),
            "cwe": "CWE-918",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _get_function_name(node: Any) -> str | None:
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") == "name":
                raw = getattr(child, "text", None)
                if isinstance(raw, bytes):
                    return raw.decode("utf-8")
                if isinstance(raw, str):
                    return raw
        return None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") == "arguments":
                return [
                    argument
                    for argument in getattr(child, "children", [])
                    if getattr(argument, "type", "") == "argument"
                ]
        return []

    @staticmethod
    def _text(node: Any) -> str:
        raw = getattr(node, "text", None)
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return raw if isinstance(raw, str) else ""


__all__ = ["PhpSSRFAstRule"]
