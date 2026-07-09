"""PHP XSS AST rule — Tree-sitter based."""

from __future__ import annotations

from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import (
    _PHP_SUPERGLOBALS,
    _subtree_contains_unsafe_php_user_input,
)

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any  # type: ignore[misc,assignment]


class PhpXSSAstRule(SecurityRule):
    """Detect XSS (unescaped output) in PHP."""

    SANITIZERS = frozenset({"htmlspecialchars", "htmlentities"})
    OUTPUT_FUNCS = frozenset({"printf", "vprintf", "exit", "die"})
    HTML_OUTPUT_VARS = frozenset({"html", "body", "output", "content", "response", "page"})
    DIRECT_SUPERGLOBALS = frozenset({"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES"})
    HIGH_RISK_SOURCE_PREFIXES = (
        "php_get",
        "php_post",
        "php_request",
        "php_cookie",
        "php_files",
        "php_input_stream",
    )
    RECENT_TAINT_WINDOW = 8
    MAX_TAINT_VARS_IN_HTML_APPEND = 2

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
            self._check_output_node(node, context, "echo")
        # print_intrinsic: print $name;
        elif node.type == "print_intrinsic":
            self._check_output_node(node, context, "print")
        # function_call_expression: printf(), exit(), die()
        elif node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name in self.OUTPUT_FUNCS:
                self._check_output_node(node, context, func_name)
        # short echo tag: <?= $name ?>
        elif node.type == "expression_statement" and self._is_short_echo_expression(node):
            self._check_output_node(node, context, "short echo")
        # augmented_assignment_expression: $html .= "<div>{$name}</div>";
        elif node.type == "augmented_assignment_expression":
            self._check_augmented_html_assignment(node, context)

    def _check_output_node(self, node: Any, context: AnalysisContext, output_name: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        if not _subtree_contains_unsafe_php_user_input(node, context, sanitizers=self.SANITIZERS):
            return

        self._reported.add(line)
        finding = {
            "type": "XSS_RISK",
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": line,
            "details": f"PHP: {output_name} 输出包含用户输入且未经 HTML 转义，存在 XSS 风险。",
        }
        finding.update(tree_sitter_node_to_range(node))
        context.add_finding(finding)

    def _check_augmented_html_assignment(self, node: Any, context: AnalysisContext) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return

        children = list(getattr(node, "children", []))
        if len(children) < 3:
            return

        left = children[0]
        op = self._text(children[1]).strip() if len(children) >= 2 else ""
        right = children[-1]
        if getattr(left, "type", "") != "variable_name" or op != ".=":
            return

        left_name = self._text(left).lstrip("$").lower()
        if left_name not in self.HTML_OUTPUT_VARS:
            return
        if not self._looks_like_html_fragment(right):
            return

        if self._contains_direct_superglobal(right) or self._contains_recent_high_risk_taint(
            right,
            context,
            sink_line=line,
        ):
            self._reported.add(line)
            finding = {
                "type": "XSS_RISK",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line,
                "details": (f"PHP: ${left_name} 拼接 HTML 片段时包含未转义用户输入，可能在后续输出阶段触发 XSS。"),
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)
            return

    def _looks_like_html_fragment(self, node: Any) -> bool:
        text = self._text(node)
        return "<" in text and ">" in text

    def _contains_direct_superglobal(self, node: Any) -> bool:
        if node is None:
            return False
        node_type = getattr(node, "type", "")

        if node_type == "subscript_expression":
            base = self._subscript_base_var(node)
            if base in self.DIRECT_SUPERGLOBALS:
                return True
        elif node_type == "variable_name":
            var_text = self._text(node).lstrip("$")
            if var_text in self.DIRECT_SUPERGLOBALS:
                return True

        for child in getattr(node, "children", []):
            if self._contains_direct_superglobal(child):
                return True
        return False

    def _contains_recent_high_risk_taint(
        self,
        node: Any,
        context: AnalysisContext,
        *,
        sink_line: int,
    ) -> bool:
        var_names = self._collect_variable_names(node)
        if not var_names:
            return False

        # 兼顾 SQLI 页面常见输出：<pre>ID: {$id} ... {$first} ... {$last}</pre>
        # 该场景中 source 到 sink 可能跨越较多行，不适用 RECENT_TAINT_WINDOW。
        if "id" in var_names and len(var_names) >= 3:
            if self._is_high_risk_tainted_var("id", context, sink_line=sink_line, require_recent=False):
                return True

        if len(var_names) > self.MAX_TAINT_VARS_IN_HTML_APPEND:
            return False

        for var_name in var_names:
            if self._is_high_risk_tainted_var(var_name, context, sink_line=sink_line, require_recent=True):
                return True
        return False

    def _is_high_risk_tainted_var(
        self,
        var_name: str,
        context: AnalysisContext,
        *,
        sink_line: int,
        require_recent: bool,
    ) -> bool:
        if not (context.is_var_tainted(var_name) or context.is_var_tainted("$" + var_name)):
            return False
        if context.is_var_sanitized(var_name) or context.is_var_sanitized("$" + var_name):
            return False
        source = context.get_taint_source(var_name) or context.get_taint_source("$" + var_name)
        if source is None:
            return False

        source_type = str(getattr(source, "source_type", "") or "").lower()
        if not source_type.startswith(self.HIGH_RISK_SOURCE_PREFIXES):
            return False
        if not require_recent:
            return True

        source_line = getattr(source, "line", None)
        if not isinstance(source_line, int) or source_line <= 0:
            return False
        if source_line > sink_line:
            return False
        return (sink_line - source_line) <= self.RECENT_TAINT_WINDOW

    def _collect_variable_names(self, node: Any) -> set[str]:
        names: set[str] = set()

        def _walk(cur: Any, parent_type: str = "") -> None:
            if cur is None:
                return
            cur_type = getattr(cur, "type", "")
            if cur_type == "variable_name":
                var_text = self._text(cur).lstrip("$")
                if var_text and var_text not in _PHP_SUPERGLOBALS and parent_type != "subscript_expression":
                    names.add(var_text)
            for child in getattr(cur, "children", []):
                _walk(child, cur_type)

        _walk(node)
        return names

    def _subscript_base_var(self, node: Any) -> str:
        if getattr(node, "type", "") != "subscript_expression":
            return ""
        for child in getattr(node, "children", []):
            if getattr(child, "type", "") == "variable_name":
                return self._text(child).lstrip("$")
        return ""

    def _is_short_echo_expression(self, node: Any) -> bool:
        previous = getattr(node, "prev_sibling", None)
        return getattr(previous, "type", "") == "php_tag" and self._text(previous).lstrip().startswith("<?=")

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
                raw = getattr(c, "text", None)
                if isinstance(raw, bytes):
                    return raw.decode("utf-8")
                if isinstance(raw, str):
                    return raw
        return None

    @staticmethod
    def _text(node: Any) -> str:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return ""


__all__ = ["PhpXSSAstRule"]
