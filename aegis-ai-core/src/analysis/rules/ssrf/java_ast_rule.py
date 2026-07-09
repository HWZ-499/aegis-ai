"""Java SSRF AST rule."""

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

_JAVA_USER_INPUT_METHODS = frozenset(
    {
        "getParameter",
        "getParameterValues",
        "getHeader",
        "getQueryString",
        "getRequestURI",
        "getPathInfo",
        "getBody",
    }
)


class JavaSSRFAstRule(SecurityRule):
    """Detect user-controlled URLs passed to common Java HTTP clients."""

    URL_FIRST_ARG_METHODS = frozenset(
        {
            "getForObject",
            "getForEntity",
            "postForObject",
            "postForEntity",
            "exchange",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="SSRF_JAVA_AST", severity="High", languages=["java"])
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return
        if node.type != "method_invocation":
            return

        method_name = self._get_method_name(node)
        arguments = self._get_arguments(node)
        if method_name in self.URL_FIRST_ARG_METHODS and arguments:
            if self._is_http_client_call(node) and self._subtree_has_user_input(arguments[0], context):
                self._report(node, context, method_name)
            return

        if method_name == "send" and arguments:
            if self._is_http_client_call(node) and self._subtree_has_user_input(arguments[0], context):
                self._report(node, context, "HttpClient.send")
            return

        if method_name in {"openConnection", "openStream"}:
            receiver = self._get_receiver(node)
            if receiver is not None and self._subtree_has_user_input(receiver, context):
                self._report(node, context, f"URL.{method_name}")

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        if getattr(node, "type", "") == "method_invocation":
            if self._is_java_user_input_call(node):
                return True
            return any(self._subtree_has_user_input(arg, context) for arg in self._get_arguments(node))

        if is_user_input_node(node, context, language="java"):
            return True
        return any(self._subtree_has_user_input(child, context) for child in getattr(node, "children", []))

    def _is_java_user_input_call(self, node: Any) -> bool:
        receiver = self._get_receiver_name(node)
        method_name = self._get_method_name(node)
        return receiver in {"request", "req"} and method_name in _JAVA_USER_INPUT_METHODS

    @staticmethod
    def _is_http_client_call(node: Any) -> bool:
        raw = getattr(node, "text", None)
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw if isinstance(raw, str) else ""
        normalized = text.lower()
        return any(
            marker in normalized
            for marker in (
                "resttemplate",
                "webclient",
                "httpclient",
                "client.",
                "client()",
            )
        )

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
                f"Java: {sink_name}() 的请求目标包含用户输入，可能导致 SSRF（CWE-918）。"
                "建议使用协议和域名白名单，并拒绝环回、内网和云元数据地址。"
            ),
            "cwe": "CWE-918",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        identifiers = [child for child in getattr(node, "children", []) if getattr(child, "type", "") == "identifier"]
        if not identifiers:
            return None
        raw = getattr(identifiers[-1], "text", None)
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return raw if isinstance(raw, str) else None

    @staticmethod
    def _get_receiver_name(node: Any) -> str | None:
        receiver = JavaSSRFAstRule._get_receiver(node)
        if receiver is None or getattr(receiver, "type", "") != "identifier":
            return None
        raw = getattr(receiver, "text", None)
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return raw if isinstance(raw, str) else None

    @staticmethod
    def _get_receiver(node: Any) -> Any | None:
        children = list(getattr(node, "children", []))
        if len(children) >= 3 and getattr(children[1], "type", "") == ".":
            return children[0]
        return None

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


__all__ = ["JavaSSRFAstRule"]
