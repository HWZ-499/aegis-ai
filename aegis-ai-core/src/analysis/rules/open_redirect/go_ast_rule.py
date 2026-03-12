"""
open_redirect.go_ast_rule

Go Open Redirect AST/污点规则。

检测目标：
1. Tree-sitter AST 节点级分析（visit）：
   - http.Redirect(w, r, userInput, code)
   - c.Redirect(code, userInput) (Gin)
   - ctx.Redirect(code, userInput) (Echo)
2. TaintGraph 路径分析（after_file，兜底）。
"""

from __future__ import annotations

from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    safe_find_paths,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any  # type: ignore[misc,assignment]


class GoOpenRedirectAstRule(SecurityRule):
    """
    基于 Tree-sitter AST + TaintGraph 的 Go Open Redirect 检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="OPEN_REDIRECT_GO_TAINT",
            severity="Medium",
            languages=["go"],
        )
        self._reported_lines: set[int] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported_lines = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not TREE_SITTER_AVAILABLE or not isinstance(node, Node):
            return

        if node.type == "call_expression":
            self._check_call_expression(node, context)

    def _check_call_expression(self, node: Any, context: AnalysisContext) -> None:
        func_name, pkg_name = self._get_qualified_name(node)
        if func_name is None:
            return

        # http.Redirect(w, r, url, statusCode) — url 是第 3 个参数
        if func_name == "Redirect" and pkg_name == "http":
            args = self._get_arguments(node)
            if len(args) >= 3:
                url_arg = args[2]
                if self._subtree_has_user_input(url_arg, context):
                    self._report(node, context, "http.Redirect")
            return

        # Gin/Echo: c.Redirect(code, url) — url 是第 2 个参数
        if func_name == "Redirect" and pkg_name in ("c", "ctx", "context"):
            args = self._get_arguments(node)
            if len(args) >= 2:
                url_arg = args[1]
                if self._subtree_has_user_input(url_arg, context):
                    self._report(node, context, f"{pkg_name}.Redirect")
            return

    def after_file(self, context: AnalysisContext) -> None:
        """TaintGraph 兜底。"""
        graph = getattr(context, "taint_graph", None)
        if graph is None:
            return

        reported_sinks: set[str] = set()
        paths = safe_find_paths(graph, self.rule_id)

        for path in paths:
            if getattr(path, "is_sanitized", False):
                continue
            sink = getattr(path, "sink_node", None)
            source = getattr(path, "source_node", None)
            if sink is None or source is None:
                continue
            sink_id = getattr(sink, "id", "")
            if not sink_id or sink_id in reported_sinks:
                continue
            category = (sink.extras or {}).get("category") if hasattr(sink, "extras") else None
            if category != "open_redirect":
                continue
            line_no = getattr(sink, "line", 0) or 0
            if line_no in self._reported_lines:
                continue
            reported_sinks.add(sink_id)
            src_expr = getattr(source, "name", "") or getattr(source, "code_snippet", "")
            sink_expr = getattr(sink, "name", "") or getattr(sink, "code_snippet", "")
            finding: dict[str, Any] = {
                "type": "OPEN_REDIRECT",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": (
                    "检测到 Go 代码中用户可控输入直接用于 http.Redirect 跳转目标，"
                    "可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。"
                ),
                "source_expr": src_expr,
                "sink_expr": sink_expr,
            }
            context.add_finding(finding)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    @staticmethod
    def _get_node_text(node: Any) -> str | None:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return None

    @staticmethod
    def _get_qualified_name(node: Any) -> tuple[str | None, str | None]:
        for child in node.children:
            if child.type == "selector_expression":
                parts = []
                for sub in child.children:
                    if sub.type in ("identifier", "field_identifier"):
                        text = sub.text
                        parts.append(text.decode("utf-8") if isinstance(text, bytes) else str(text))
                if len(parts) >= 2:
                    return parts[-1], parts[0]
                if len(parts) == 1:
                    return parts[0], None
            if child.type == "identifier":
                text = child.text
                name = text.decode("utf-8") if isinstance(text, bytes) else str(text)
                return name, None
        return None, None

    @staticmethod
    def _get_arguments(node: Any) -> list[Any]:
        for child in node.children:
            if child.type == "argument_list":
                return [c for c in child.children if c.type not in ("(", ")", ",")]
        return []

    def _subtree_has_user_input(self, node: Any, context: AnalysisContext) -> bool:
        if is_user_input_node(node, context, language="go"):
            return True
        for child in getattr(node, "children", []) or []:
            if self._subtree_has_user_input(child, context):
                return True
        return False

    def _report(self, node: Any, context: AnalysisContext, func_desc: str) -> None:
        line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
        if line in self._reported_lines:
            return
        self._reported_lines.add(line)
        finding: dict[str, Any] = {
            "type": "OPEN_REDIRECT",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": (
                f"检测到 {func_desc}() 调用中包含用户可控输入作为跳转目标，"
                "可能导致 Open Redirect 漏洞，建议使用域名白名单或固定路径映射。"
            ),
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)


__all__ = ["GoOpenRedirectAstRule"]
